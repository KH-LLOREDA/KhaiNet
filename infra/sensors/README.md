# KhaiNet — Sensores reales

## Arquitectura

```
PCAP → Zeek (logs JSON) ──────→ Filebeat → Kafka topics
PCAP → Suricata (eve.json) ──→ Filebeat → Kafka topics
      → Wazuh (alerts.json) ──→ Filebeat → Kafka topics
```

## Componentes

| Container | IP | Función | Imagen |
|-----------|----|---------| ----- |
| khainet-zeek | 172.25.0.9 | Sensor de tráfico (PCAP → logs JSON) | zeek/zeek:7.0.0 |
| khainet-suricata | 172.25.0.10 | IDS/IPS (PCAP → eve.json) | jasonish/suricata:7.0.0 |
| khainet-wazuh | 172.25.0.11 | HIDS/SIEM (eventos de sistema) | wazuh/wazuh-manager:4.7.0 |
| khainet-filebeat | 172.25.0.12 | Shipper (logs → Kafka) | docker.elastic.co/beats/filebeat:7.16.3 |

## Routing de topics Kafka

| Log | Topic Kafka | Tabla ClickHouse | Índice OpenSearch |
|-----|-------------|-----------------|-------------------|
| Zeek conn.log | zeek-conn | zeek-conn | zeek-conn |
| Zeek dns.log | zeek-dns | zeek-dns | zeek-dns |
| Zeek http.log | zeek-http | zeek-http | zeek-http |
| Zeek ssl.log | zeek-ssl | zeek-ssl | zeek-ssl |
| Suricata eve.json | suricata-alerts | — | suricata-alerts |
| Wazuh alerts.json | wazuh-events | — | wazuh-events |

## PCAP demo

`pcap/khainet-demo.pcap` — 319 paquetes con:
- Tráfico normal: DNS, HTTP, HTTPS, SSH, ICMP
- Tráfico sospechoso: port scan, C2 beaconing, DNS tunneling, data exfiltration

## Despliegue

```bash
# Crear volúmenes
docker volume create khainet-zeek-pcap khainet-zeek-logs \
  khainet-suricata-pcap khainet-suricata-logs \
  khainet-wazuh-data khainet-wazuh-logs khainet-wazuh-etc

# Copiar PCAP al volumen
docker run --rm -v khainet-zeek-pcap:/data -v $(pwd)/pcap:/src alpine cp /src/khainet-demo.pcap /data/
docker run --rm -v khainet-suricata-pcap:/data -v $(pwd)/pcap:/src alpine cp /src/khainet-demo.pcap /data/

# Levantar
docker compose up -d
```
