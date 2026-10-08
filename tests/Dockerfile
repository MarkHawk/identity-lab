# Headless browser for scripts/test.sh. Runs with host networking so it
# reaches the lab exactly as a user's browser would, at LAB_HOST:818x.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0
# certutil: add the lab CA to Chromium's NSS trust store at runtime, so TLS
# is verified for real instead of ignoring certificate errors.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnss3-tools=2:3.98-1ubuntu0.2 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt
WORKDIR /tests
COPY entrypoint.sh e2e.py ./
ENTRYPOINT ["/tests/entrypoint.sh"]
