#!/usr/bin/env python3
"""Build detection-consumer and brain-consumer Docker images on docker02.

Uses Portainer API to create a temporary build container that:
1. Mounts the workspace files
2. Runs docker build for each Dockerfile
3. Tags the images

Usage:
    python3 infra/build_consumers.py
"""

import json
import requests
import time
import sys
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore")

PORTAINER_URL = "https://172.26.10.98:9443"
PORTAINER_USER = "admin"
PORTAINER_PASS = "o9KN78GoacDonx"
ENDPOINT_ID = 3  # docker02


def get_token():
    resp = requests.post(
        f"{PORTAINER_URL}/api/auth",
        json={"username": PORTAINER_USER, "password": PORTAINER_PASS},
        verify=False,
    )
    return resp.json()["jwt"]


def run_exec(container_id, cmd, token):
    """Execute a command in a container via Portainer API."""
    headers = {"Authorization": f"Bearer {token}"}

    # Create exec instance
    exec_resp = requests.post(
        f"{PORTAINER_URL}/api/endpoints/{ENDPOINT_ID}/docker/containers/{container_id}/exec",
        headers=headers,
        json={
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": cmd,
        },
        verify=False,
    )
    exec_id = exec_resp.json()["Id"]

    # Start exec
    start_resp = requests.post(
        f"{PORTAINER_URL}/api/endpoints/{ENDPOINT_ID}/docker/exec/{exec_id}/start",
        headers=headers,
        json={"Detach": False, "Tty": False},
        verify=False,
        stream=True,
    )
    output = start_resp.content.decode("utf-8", errors="replace")
    return "".join(c for c in output if c.isprintable() or c in "\n\r")


def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Find a container with Docker socket access (kafka-connect has Docker access)
    # Actually, we need to build images. Let's use the Portainer build endpoint.
    # Portainer doesn't have a direct build API, but we can:
    # 1. Create a temporary container with Docker socket mounted
    # 2. Run docker build inside it

    # Alternative: use Portainer's /api/endpoints/{id}/docker/build endpoint
    # This endpoint accepts a tarball with Dockerfile and context

    print("=== Building Docker images on docker02 ===\n")

    # We'll create tarballs of each build context and send them to the Docker build API
    import tarfile
    import io
    import os

    workspace = "/workspace"

    builds = [
        {
            "name": "khainet-detection-consumer",
            "dockerfile": "infra/Dockerfile.detection-consumer",
            "context_dirs": ["detection/", "pipeline/"],
            "context_files": [
                "infra/Dockerfile.detection-consumer",
                "pipeline/pipeline_config_prod.yaml",
            ],
        },
        {
            "name": "khainet-brain-consumer",
            "dockerfile": "infra/Dockerfile.brain-consumer",
            "context_dirs": ["brain/"],
            "context_files": ["infra/Dockerfile.brain-consumer"],
        },
    ]

    for build in builds:
        print(f"\n=== Building {build['name']} ===")

        # Create tarball
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            # Add Dockerfile as "Dockerfile"
            dockerfile_path = os.path.join(workspace, build["dockerfile"])
            if os.path.exists(dockerfile_path):
                with open(dockerfile_path, "rb") as f:
                    info = tarfile.TarInfo(name="Dockerfile")
                    data = f.read()
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                print(f"  Added Dockerfile")
            else:
                print(f"  ERROR: Dockerfile not found at {dockerfile_path}")
                continue

            # Add context directories
            for ctx_dir in build["context_dirs"]:
                full_path = os.path.join(workspace, ctx_dir)
                if os.path.isdir(full_path):
                    arcname = ctx_dir.rstrip("/")
                    tar.add(full_path, arcname=arcname, recursive=True)
                    file_count = sum(len(files) for _, _, files in os.walk(full_path))
                    print(f"  Added {ctx_dir} ({file_count} files)")
                else:
                    print(f"  WARNING: {ctx_dir} not found")

            # Add extra context files
            for ctx_file in build["context_files"]:
                full_path = os.path.join(workspace, ctx_file)
                if os.path.exists(full_path):
                    arcname = ctx_file
                    tar.add(full_path, arcname=arcname)
                    print(f"  Added {ctx_file}")

        tar_buffer.seek(0)
        tar_data = tar_buffer.read()
        print(f"  Tarball size: {len(tar_data)} bytes")

        # Send to Docker build API via Portainer
        # The Dockerfile in the tarball is at root, so dockerfile=Dockerfile
        build_url = f"{PORTAINER_URL}/api/endpoints/{ENDPOINT_ID}/docker/build"
        params = {
            "t": f"{build['name']}:latest",
            "dockerfile": "Dockerfile",
            "rm": "true",
        }

        print(f"  Sending build request...")
        resp = requests.post(
            build_url,
            headers={**headers, "Content-Type": "application/x-tar"},
            params=params,
            data=tar_data,
            verify=False,
            stream=True,
        )

        if resp.status_code == 200:
            # Parse build output (streamed JSON lines)
            for line in resp.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "stream" in data:
                            print(f"  {data['stream'].rstrip()}")
                        elif "error" in data:
                            print(f"  ERROR: {data['error']}")
                    except json.JSONDecodeError:
                        pass
            print(f"  ✅ Build complete: {build['name']}:latest")
        else:
            print(f"  ❌ Build failed: HTTP {resp.status_code}")
            print(f"  Response: {resp.text[:500]}")

    print("\n=== All builds complete ===")


if __name__ == "__main__":
    main()
