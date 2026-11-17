FROM python:3.13-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir coverage==7.17.3
WORKDIR /work
COPY . /work/
