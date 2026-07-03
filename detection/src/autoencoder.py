"""Autoencoder detector for network anomaly detection.

Uses a dense (MLP) autoencoder implemented in PyTorch. The model learns to
reconstruct normal traffic patterns; high reconstruction error indicates
anomaly. The threshold is set at the p99 of training reconstruction errors.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
import torch
import torch.nn as nn

from src.feature_engineering import get_feature_matrix
from src.models import FeatureVector, ModelResult

log = structlog.get_logger()


class _DenseAutoencoder(nn.Module):
    """Dense (MLP) autoencoder: input → hidden_dims → bottleneck → hidden_dims_rev → input."""

    def __init__(self, input_dim: int, hidden_dims: list[int]):
        super().__init__()
        # Encoder: input → hidden_dims[0] → ... → hidden_dims[-1]
        encoder_layers: list[nn.Module] = []
        prev = input_dim
        for dim in hidden_dims:
            encoder_layers.append(nn.Linear(prev, dim))
            encoder_layers.append(nn.ReLU())
            prev = dim
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder: hidden_dims[-1] → reversed → input
        decoder_layers: list[nn.Module] = []
        reversed_dims = list(reversed(hidden_dims))
        prev = hidden_dims[-1]
        for dim in reversed_dims[1:]:
            decoder_layers.append(nn.Linear(prev, dim))
            decoder_layers.append(nn.ReLU())
            prev = dim
        decoder_layers.append(nn.Linear(prev, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AutoencoderDetector:
    """Autoencoder-based anomaly detector using PyTorch.

    Architecture: input → 64 → 32 → 16 → 32 → 64 → input (configurable).
    Activation: ReLU in hidden layers, identity on output.
    Loss: MSE. Threshold: p99 of training reconstruction errors.

    Attributes:
        input_dim: Number of input features.
        hidden_dims: Hidden layer dimensions for the encoder.
        lr: Learning rate.
        epochs: Number of training epochs.
        batch_size: Mini-batch size.
        random_state: Random seed for reproducibility.
        threshold: Reconstruction error threshold (p99 of training).
        model: The PyTorch autoencoder model.
        scaler: StandardScaler used for normalization.
        training_losses: Loss per epoch during training.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dims: list[int] | None = None,
        lr: float = 1e-3,
        epochs: int = 50,
        batch_size: int = 32,
        random_state: int = 42,
        threshold_percentile: int = 99,
    ):
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims or [64, 32, 16]
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.random_state = random_state
        self.threshold_percentile = threshold_percentile
        self.threshold: float = 0.0
        self.model: _DenseAutoencoder | None = None
        self.scaler: Any = None
        self.training_losses: list[float] = []

    def _build_model(self) -> _DenseAutoencoder:
        """Build the autoencoder model."""
        return _DenseAutoencoder(self.input_dim, self.hidden_dims)

    def fit(self, features: list[FeatureVector], scaler: Any = None) -> None:
        """Train the autoencoder on normalized features.

        Args:
            features: List of FeatureVector objects.
            scaler: Optional pre-fitted StandardScaler.
        """
        from src.feature_engineering import normalize_features

        torch.manual_seed(self.random_state)
        np.random.seed(self.random_state)

        if scaler is not None:
            self.scaler = scaler

        # Normalize if not already done
        if features and not features[0].normalized:
            features, self.scaler = normalize_features(features)

        X = get_feature_matrix(features)
        if X.shape[0] == 0:
            log.warning("no_features_to_fit_ae")
            return

        # Update input_dim based on actual feature count
        self.input_dim = X.shape[1]
        self.model = self._build_model()

        X_tensor = torch.FloatTensor(X)
        dataset = torch.utils.data.TensorDataset(X_tensor, X_tensor)
        dataloader = torch.utils.data.DataLoader(
            dataset, batch_size=self.batch_size, shuffle=True
        )

        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.lr)

        self.training_losses = []
        self.model.train()
        for epoch in range(self.epochs):
            epoch_loss = 0.0
            n_batches = 0
            for batch_x, _ in dataloader:
                optimizer.zero_grad()
                reconstructed = self.model(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            self.training_losses.append(avg_loss)

        # Compute reconstruction errors on training set
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((reconstructed - X_tensor) ** 2, dim=1).numpy()

        self.threshold = float(np.percentile(errors, self.threshold_percentile))

        log.info(
            "autoencoder_fitted",
            n_samples=X.shape[0],
            n_features=X.shape[1],
            epochs=self.epochs,
            threshold=self.threshold,
            final_loss=self.training_losses[-1] if self.training_losses else 0.0,
        )

    def get_reconstruction_errors(self, features: list[FeatureVector]) -> list[float]:
        """Compute reconstruction error for each feature vector.

        Args:
            features: List of FeatureVector objects.

        Returns:
            List of reconstruction errors (MSE per sample).
        """
        if self.model is None:
            log.warning("ae_model_not_fitted")
            return []

        # Normalize if needed
        if features and not features[0].normalized and self.scaler is not None:
            from src.feature_engineering import normalize_features

            features, _ = normalize_features(features, self.scaler)

        X = get_feature_matrix(features)
        if X.shape[0] == 0:
            return []

        X_tensor = torch.FloatTensor(X)
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((reconstructed - X_tensor) ** 2, dim=1).numpy()

        return [float(e) for e in errors]

    def predict(self, features: list[FeatureVector]) -> list[ModelResult]:
        """Predict anomaly scores based on reconstruction error.

        Score = min(1.0, error / (threshold * 2)).
        is_anomaly = error > threshold.

        Args:
            features: List of FeatureVector objects.

        Returns:
            List of ModelResult with scores in 0-1 range.
        """
        if self.model is None:
            log.warning("ae_model_not_fitted")
            return []

        errors = self.get_reconstruction_errors(features)
        results: list[ModelResult] = []

        for i, (vector, error) in enumerate(zip(features, errors)):
            score = (
                min(1.0, error / (self.threshold * 2)) if self.threshold > 0 else 0.0
            )
            score = float(np.clip(score, 0.0, 1.0))
            is_anomaly = error > self.threshold
            results.append(
                ModelResult(
                    model_name="autoencoder",
                    timestamp=vector.timestamp,
                    src_ip=vector.src_ip,
                    score=score,
                    is_anomaly=is_anomaly,
                    threshold=self.threshold,
                    details={
                        "reconstruction_error": error,
                        "dst_ip": vector.dst_ip,
                        "dst_port": vector.dst_port,
                    },
                )
            )

        log.debug(
            "ae_predictions",
            count=len(results),
            n_anomalies=sum(r.is_anomaly for r in results),
        )
        return results

    def get_state_dict(self) -> dict[str, Any]:
        """Get model state for persistence."""
        if self.model is None:
            return {}
        return {
            "state_dict": self.model.state_dict(),
            "input_dim": self.input_dim,
            "hidden_dims": self.hidden_dims,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "lr": self.lr,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "random_state": self.random_state,
            "training_losses": self.training_losses,
        }

    def load_state_dict(self, state: dict[str, Any]) -> None:
        """Load model state from persistence."""
        self.input_dim = state["input_dim"]
        self.hidden_dims = state["hidden_dims"]
        self.threshold = state["threshold"]
        self.threshold_percentile = state.get("threshold_percentile", 99)
        self.lr = state.get("lr", 1e-3)
        self.epochs = state.get("epochs", 50)
        self.batch_size = state.get("batch_size", 32)
        self.random_state = state.get("random_state", 42)
        self.training_losses = state.get("training_losses", [])
        self.model = self._build_model()
        self.model.load_state_dict(state["state_dict"])
        self.model.eval()
