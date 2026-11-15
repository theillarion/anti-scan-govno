FROM python:3.13-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends nftables tzdata && rm -rf /var/lib/apt/lists/*
COPY nftguard.py /usr/local/bin/nftguard
HEALTHCHECK --interval=5m --timeout=15s --start-period=5m --retries=3 CMD ["python3", "/usr/local/bin/nftguard", "healthcheck"]
CMD ["python3", "/usr/local/bin/nftguard"]
