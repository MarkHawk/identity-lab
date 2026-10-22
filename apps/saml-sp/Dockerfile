# SAML service provider sample app (Flask + python3-saml).
#
# lxml and xmlsec are compiled from source against Debian's libxml2 and
# libxmlsec1: mixing their binary wheels (each bundling its own libxml2)
# is a well-known cause of "lxml & xmlsec libxml2 library version mismatch".

ARG PYTHON_IMAGE=python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26

FROM ${PYTHON_IMAGE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc \
      pkg-config \
      zlib1g-dev \
      libxml2-dev \
      libxslt1-dev \
      libxmlsec1-dev \
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
      libxml2 \
      libxslt1.1 \
      libxmlsec1 \
      libxmlsec1-openssl \
      libfaketime \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls -d /usr/lib/*/faketime)" /usr/local/lib/faketime
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app
COPY app.py accesslog.py ./
COPY templates ./templates
ENV PYTHONUNBUFFERED=1
EXPOSE 8181
# --timeout 0: the clock-skew scenario jumps the wall clock; gunicorn's
# worker heartbeat must not mistake that for a hung worker.
# Access log through accesslog.py: one-time login values are masked.
CMD ["gunicorn", "--bind", "0.0.0.0:8181", \
     "--certfile", "/etc/idlab/tls.crt", "--keyfile", "/etc/idlab/tls.key", \
     "--workers", "1", "--threads", "4", "--timeout", "0", \
     "--access-logfile", "-", "--logger-class", "accesslog.MaskingLogger", "app:app"]
