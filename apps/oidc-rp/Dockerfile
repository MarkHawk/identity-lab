# OIDC relying party sample app (Flask + Authlib).
FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /app
COPY app.py ./
COPY templates ./templates
EXPOSE 8182
CMD ["gunicorn", "--bind", "0.0.0.0:8182", \
     "--certfile", "/etc/idlab/tls.crt", "--keyfile", "/etc/idlab/tls.key", \
     "--workers", "1", "--threads", "4", \
     "--access-logfile", "-", "app:app"]
