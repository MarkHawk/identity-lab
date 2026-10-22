# OIDC relying party sample app (Flask + Authlib).
FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /app
COPY app.py accesslog.py gunicorn.conf.py ./
COPY templates ./templates
EXPOSE 8182
# Bind address, TLS and the masking access log: see gunicorn.conf.py.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
