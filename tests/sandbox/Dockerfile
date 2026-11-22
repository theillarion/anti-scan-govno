FROM python:3.13-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/nftguard-requirements.txt
RUN pip install --no-cache-dir coverage==7.17.3 -r /tmp/nftguard-requirements.txt
WORKDIR /work
COPY . /work/
