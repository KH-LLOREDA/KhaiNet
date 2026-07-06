#!/usr/bin/env python3
"""
deploy_sensors.py — Despliegue de sensores KhaiNet via Docker API (Portainer)

Despliega Zeek, Suricata, Wazuh y Filebeat en docker02 usando la Docker API
a través de Portainer. No usa docker compose CLI; usa la Docker API directamente.

Uso:
    python3 deploy_sensors.py
"""

import requests
import json
import time
import sys
import os
import base64

# === Config ===
PORTAINER_URL = "http://172.26.10.98:9000"
ENDPOINT_ID = 3  # docker02
KAFKA_BROKER = "172.25.0.2:9092"
NETWORK_NAME = "khainet-network"

# Credenciales se obtienen de Vaultwarden en runtime
# Aquí se inyectan via variables de entorno o se pasan como argumento


def get_jwt():
    """Autenticar con Portainer y obtener JWT"""
    # La password se inyecta desde el entorno
    password = os.environ.get("PORTAINER_PASS")
    if not password:
        print("ERROR: PORTAINER_PASS no definida")
        sys.exit(1)
    resp = requests.post(
        f"{PORTAINER_URL}/api/auth",
        json={"username": "admin", "password": password},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"ERROR auth: {resp.status_code} {resp.text}")
        sys.exit(1)
    return resp.json()["jwt"]


def docker_api(jwt, method, path, **kwargs):
    """Wrapper para la Docker API via Portainer"""
    url = f"{PORTAINER_URL}/api/endpoints/{ENDPOINT_ID}/docker{path}"
    headers = {"Authorization": f"Bearer {jwt}"}
    resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    return resp


def create_volume(jwt, name):
    """Crear un volumen Docker"""
    resp = docker_api(jwt, "POST", "/volumes/create", json={"Name": name})
    if resp.status_code in (201, 204):
        print(f"  ✓ Volumen creado: {name}")
    else:
        try:
            err = resp.json()
            if "already exists" in str(err):
                print(f"  ⊙ Volumen ya existe: {name}")
            else:
                print(f"  ✗ Error creando volumen {name}: {resp.status_code} {err}")
        except:
            print(f"  ⊙ Volumen ya existe: {name}")


def copy_to_volume(jwt, volume_name, file_path, dest_name):
    """Copiar un archivo del host a un volumen Docker usando un container temporal"""
    # Crear container temporal con el volumen montado
    resp = docker_api(
        jwt,
        "POST",
        "/containers/create",
        json={
            "Image": "alpine:latest",
            "Cmd": ["sleep", "300"],
            "HostConfig": {"Binds": [f"{volume_name}:/data"]},
        },
    )
    if resp.status_code != 201:
        print(f"  ✗ Error creando container temporal: {resp.status_code} {resp.text}")
        return False
    container_id = resp.json()["Id"]

    # Iniciar container
    docker_api(jwt, "POST", f"/containers/{container_id}/start")

    # Copiar archivo al container (tar archive)
    import tarfile
    import io

    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        info = tarfile.TarInfo(name=dest_name)
        with open(file_path, "rb") as f:
            data = f.read()
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    tar_stream.seek(0)

    # PUT archive al container en /data/
    resp = docker_api(
        jwt,
        "PUT",
        f"/containers/{container_id}/archive",
        params={"path": "/data"},
        data=tar_stream.read(),
        headers={"Content-Type": "application/x-tar"},
    )

    # Limpiar container temporal
    docker_api(jwt, "DELETE", f"/containers/{container_id}?force=true")

    if resp.status_code == 200:
        print(f"  ✓ Archivo copiado: {file_path} → {volume_name}:{dest_name}")
        return True
    else:
        print(f"  ✗ Error copiando archivo: {resp.status_code} {resp.text}")
        return False


def pull_image(jwt, image):
    """Hacer pull de una imagen Docker"""
    print(f"  Pulling image: {image}...")
    resp = docker_api(
        jwt, "POST", "/images/create", params={"fromImage": image}, timeout=300
    )
    if resp.status_code == 200:
        print(f"  ✓ Image pulled: {image}")
    else:
        print(f"  ⚠ Image pull status: {resp.status_code}")


def create_container(jwt, config):
    """Crear y arrancar un container"""
    name = config["name"]
    resp = docker_api(
        jwt, "POST", "/containers/create", params={"name": name}, json=config["body"]
    )
    if resp.status_code == 201:
        container_id = resp.json()["Id"]
        print(f"  ✓ Container creado: {name} (id={container_id[:12]})")
        # Arrancar
        start_resp = docker_api(jwt, "POST", f"/containers/{container_id}/start")
        if start_resp.status_code == 204:
            print(f"  ✓ Container arrancado: {name}")
        else:
            print(
                f"  ✗ Error arrancando {name}: {start_resp.status_code} {start_resp.text}"
            )
        return container_id
    elif resp.status_code == 409:
        print(f"  ⊙ Container ya existe: {name}")
        # Obtener ID existente
        list_resp = docker_api(
            jwt,
            "GET",
            "/containers/json",
            params={"all": True, "filters": json.dumps({"name": [name]})},
        )
        if list_resp.status_code == 200 and list_resp.json():
            container_id = list_resp.json()[0]["Id"]
            # Arrancar si está parado
            start_resp = docker_api(jwt, "POST", f"/containers/{container_id}/start")
            if start_resp.status_code == 204:
                print(f"  ✓ Container arrancado: {name}")
            return container_id
    else:
        print(f"  ✗ Error creando {name}: {resp.status_code} {resp.text[:200]}")
        return None


def main():
    print("=" * 60)
    print("KhaiNet — Despliegue de sensores reales")
    print("=" * 60)

    jwt = get_jwt()
    print(f"✓ Autenticado en Portainer (endpoint {ENDPOINT_ID} = docker02)")

    # === 1. Crear volúmenes ===
    print("\n--- Creando volúmenes ---")
    volumes = [
        "khainet-zeek-pcap",
        "khainet-zeek-logs",
        "khainet-suricata-pcap",
        "khainet-suricata-logs",
        "khainet-wazuh-data",
        "khainet-wazuh-logs",
        "khainet-wazuh-etc",
    ]
    for v in volumes:
        create_volume(jwt, v)

    # === 2. Copiar PCAP a volúmenes ===
    print("\n--- Copiando PCAP a volúmenes ---")
    pcap_path = os.path.join(os.path.dirname(__file__), "pcap", "khainet-demo.pcap")
    if os.path.exists(pcap_path):
        copy_to_volume(jwt, "khainet-zeek-pcap", pcap_path, "khainet-demo.pcap")
        copy_to_volume(jwt, "khainet-suricata-pcap", pcap_path, "khainet-demo.pcap")
    else:
        print(f"  ✗ PCAP no encontrado: {pcap_path}")

    # === 3. Copiar configs a volúmenes ===
    print("\n--- Copiando configs a volúmenes ---")
    # Suricata config
    suricata_yaml = os.path.join(os.path.dirname(__file__), "suricata", "suricata.yaml")
    if os.path.exists(suricata_yaml):
        # Crear volumen temporal para configs o usar bind mount
        pass  # Se usa bind mount en el container

    # === 4. Pull images ===
    print("\n--- Pulling images ---")
    images = [
        "zeek/zeek:7.0.0",
        "jasonish/suricata:7.0.0",
        "wazuh/wazuh-manager:4.7.0",
        "docker.elastic.co/beats/filebeat:7.16.3",
    ]
    for img in images:
        pull_image(jwt, img)

    # === 5. Crear containers ===
    print("\n--- Creando containers ---")

    # Zeek
    create_container(
        jwt,
        {
            "name": "khainet-zeek",
            "body": {
                "Image": "zeek/zeek:7.0.0",
                "Cmd": [
                    "/bin/bash",
                    "-c",
                    "echo 'Zeek esperando PCAPs...' && while true; do if ls /data/pcap/*.pcap 1>/dev/null 2>&1; then echo 'Procesando...' && for f in /data/pcap/*.pcap; do echo \"Zeek: $f\" && zeek -r $f -C LogAscii::use_json=T local && cp /usr/local/zeek/logs/* /data/logs/ 2>/dev/null || true; done; fi; sleep 30; done",
                ],
                "HostConfig": {
                    "Binds": [
                        "khainet-zeek-pcap:/data/pcap",
                        "khainet-zeek-logs:/data/logs",
                    ],
                    "NetworkMode": NETWORK_NAME,
                    "RestartPolicy": {"Name": "unless-stopped"},
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        NETWORK_NAME: {"IPAMConfig": {"IPv4Address": "172.25.0.9"}}
                    }
                },
            },
        },
    )

    # Suricata
    create_container(
        jwt,
        {
            "name": "khainet-suricata",
            "body": {
                "Image": "jasonish/suricata:7.0.0",
                "Cmd": [
                    "/bin/bash",
                    "-c",
                    "echo 'Suricata esperando PCAPs...' && while true; do if ls /data/pcap/*.pcap 1>/dev/null 2>&1; then echo 'Procesando...' && for f in /data/pcap/*.pcap; do echo \"Suricata: $f\" && suricata -r $f -l /var/log/suricata --runmode single; done; fi; sleep 30; done",
                ],
                "HostConfig": {
                    "Binds": [
                        "khainet-suricata-pcap:/data/pcap",
                        "khainet-suricata-logs:/var/log/suricata",
                    ],
                    "NetworkMode": NETWORK_NAME,
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "CapAdd": ["NET_ADMIN", "SYS_NICE"],
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        NETWORK_NAME: {"IPAMConfig": {"IPv4Address": "172.25.0.10"}}
                    }
                },
            },
        },
    )

    # Wazuh
    create_container(
        jwt,
        {
            "name": "khainet-wazuh",
            "body": {
                "Image": "wazuh/wazuh-manager:4.7.0",
                "Hostname": "khainet-wazuh",
                "Env": ["INDEXER_URL=172.25.0.5", "FILEBEAT_SSL_VERIFICATION=false"],
                "ExposedPorts": {"1514/udp": {}, "1515/tcp": {}, "55000/tcp": {}},
                "HostConfig": {
                    "Binds": [
                        "khainet-wazuh-data:/var/ossec/data",
                        "khainet-wazuh-logs:/var/ossec/logs",
                        "khainet-wazuh-etc:/var/ossec/etc",
                    ],
                    "PortBindings": {
                        "1514/udp": [{"HostPort": "1514"}],
                        "1515/tcp": [{"HostPort": "1515"}],
                        "55000/tcp": [{"HostPort": "55000"}],
                    },
                    "NetworkMode": NETWORK_NAME,
                    "RestartPolicy": {"Name": "unless-stopped"},
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        NETWORK_NAME: {"IPAMConfig": {"IPv4Address": "172.25.0.11"}}
                    }
                },
            },
        },
    )

    # Filebeat
    create_container(
        jwt,
        {
            "name": "khainet-filebeat",
            "body": {
                "Image": "docker.elastic.co/beats/filebeat:7.16.3",
                "Cmd": ["filebeat", "-e", "-c", "/usr/share/filebeat/filebeat.yml"],
                "User": "root",
                "HostConfig": {
                    "Binds": [
                        "khainet-zeek-logs:/data/zeek:ro",
                        "khainet-suricata-logs:/data/suricata:ro",
                        "khainet-wazuh-logs:/data/wazuh:ro",
                    ],
                    "NetworkMode": NETWORK_NAME,
                    "RestartPolicy": {"Name": "unless-stopped"},
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        NETWORK_NAME: {"IPAMConfig": {"IPv4Address": "172.25.0.12"}}
                    }
                },
            },
        },
    )

    # === 6. Verificar ===
    print("\n--- Verificando containers ---")
    time.sleep(5)
    resp = docker_api(jwt, "GET", "/containers/json", params={"all": True})
    if resp.status_code == 200:
        for c in resp.json():
            name = c.get("Names", ["?"])[0].lstrip("/")
            if "khainet" in name:
                state = c.get("State", "?")
                status = c.get("Status", "?")
                print(f"  {name:30s} | {state:10s} | {status}")

    print("\n✓ Despliegue completo")


if __name__ == "__main__":
    main()
