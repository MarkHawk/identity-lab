# API (resource server) that accepts Keycloak access tokens (Flask + joserfc).
FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
# pip is upgraded twice: the base image's copy and the venv's (python -m venv
# installs ensurepip's bundled pip). Older pips vendor a certifi that still
# trusts the compromised eMudhra CA keys, and a vulnerable urllib3 and msgpack;
# 26.3 is the first release to vendor fixed versions of all three.
ARG PIP_VERSION=26.3
RUN pip install --no-cache-dir "pip==${PIP_VERSION}" \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}"
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /app
COPY app.py accesslog.py gunicorn.conf.py ./
EXPOSE 8188
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
