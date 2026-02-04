# Dockerfile for Adaptive DCF Firewall (NFQUEUE)
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables libpcap-dev gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
# Needs NET_ADMIN and NFQUEUE rules on host; run with: --cap-add=NET_ADMIN --network host
CMD ["python","/app/adaptive_firewall.py"]
