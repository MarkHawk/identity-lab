# OIDC relying party sample app (Flask + Authlib).
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
COPY templates ./templates
# Fixed non-root user. compose.yaml's user: (LAB_UID) overrides it at run time,
# which the 0600 key files need; nothing here writes outside /tmp.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001
EXPOSE 8182
# Bind address, TLS and the masking access log: see gunicorn.conf.py.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
