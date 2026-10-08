# SAML service provider sample app (Flask + python3-saml).
#
# lxml and xmlsec are compiled from source against Debian's libxml2 and
# libxmlsec1: mixing their binary wheels (each bundling its own libxml2)
# is a well-known cause of "lxml & xmlsec libxml2 library version mismatch".

ARG PYTHON_IMAGE=python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26

FROM ${PYTHON_IMAGE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc=4:12.2.0-3 \
      pkg-config=1.8.1-1 \
      zlib1g-dev=1:1.2.13.dfsg-1 \
      libxml2-dev=2.9.14+dfsg-1.3~deb12u6 \
      libxslt1-dev=1.1.35-1+deb12u4 \
      libxmlsec1-dev=1.2.37-2 \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements-build.txt requirements.txt /tmp/
# lxml must be installed before xmlsec is built against it, and build
# isolation is off so the pinned build tools (not latest) are used.
RUN pip install --no-cache-dir -r /tmp/requirements-build.txt \
 && pip install --no-cache-dir --no-binary=lxml "$(grep '^lxml==' /tmp/requirements.txt)" \
 && pip install --no-cache-dir --no-build-isolation --no-binary=lxml,xmlsec \
      -r /tmp/requirements.txt

FROM ${PYTHON_IMAGE}
# libfaketime lets the clock-skew scenario shift this container's clock
# without touching the host clock (see scenarios/clock-skew.sh).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libxml2=2.9.14+dfsg-1.3~deb12u6 \
      libxslt1.1=1.1.35-1+deb12u4 \
      libxmlsec1=1.2.37-2 \
      libxmlsec1-openssl=1.2.37-2 \
      libfaketime=0.9.10-2.1 \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls -d /usr/lib/*/faketime)" /usr/local/lib/faketime
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app
COPY app.py ./
COPY templates ./templates
ENV PYTHONUNBUFFERED=1
EXPOSE 8181
# --timeout 0: the clock-skew scenario jumps the wall clock; gunicorn's
# worker heartbeat must not mistake that for a hung worker.
CMD ["gunicorn", "--bind", "0.0.0.0:8181", \
     "--certfile", "/etc/idlab/tls.crt", "--keyfile", "/etc/idlab/tls.key", \
     "--workers", "1", "--threads", "4", "--timeout", "0", \
     "--access-logfile", "-", "app:app"]
