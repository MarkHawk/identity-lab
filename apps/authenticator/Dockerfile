# The lab's authenticator app: plays an MFA user's phone (see authenticator.py).
# Python standard library only, so no packages to pin. The same pinned base
# image as the other apps.
FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
# No venv here, so only the base image's pip. Older pips vendor a certifi that
# still trusts the compromised eMudhra CA keys, and a vulnerable urllib3 and
# msgpack; 26.3 is the first release to vendor fixed versions of all three.
ARG PIP_VERSION=26.3
RUN pip install --no-cache-dir "pip==${PIP_VERSION}"
# libfaketime: the totp-clock-drift scenario shifts this container's clock,
# and only this one. qrencode: `authenticator otpauth <user> --qr`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libfaketime qrencode \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls -d /usr/lib/*/faketime)" /usr/local/lib/faketime
COPY --chmod=0755 authenticator.py /usr/local/bin/authenticator
ENV PYTHONUNBUFFERED=1
# Fixed non-root user. compose.yaml's user: (LAB_UID) overrides it at run time,
# which the 0600 key files need; nothing here writes outside /tmp.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001
# Nothing to serve: codes are read with `docker compose exec authenticator ...`.
CMD ["sleep", "infinity"]
