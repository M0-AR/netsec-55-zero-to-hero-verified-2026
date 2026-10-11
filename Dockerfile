FROM python:3.11-slim
WORKDIR /lab
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping dnsutils curl openssl tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["bash"]
