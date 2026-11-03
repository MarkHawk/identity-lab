# The lab's authenticator app: plays an MFA user's phone (see authenticator.py).
# Python standard library only, so no packages to pin. The same pinned base
# image as the other apps.
FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
# libfaketime: the totp-clock-drift scenario shifts this container's clock,
# and only this one. qrencode: `authenticator otpauth <user> --qr`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libfaketime qrencode \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls -d /usr/lib/*/faketime)" /usr/local/lib/faketime
COPY --chmod=0755 authenticator.py /usr/local/bin/authenticator
ENV PYTHONUNBUFFERED=1
# Nothing to serve: codes are read with `docker compose exec authenticator ...`.
CMD ["sleep", "infinity"]
