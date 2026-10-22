"""Gunicorn settings for the API: HTTPS with the lab certificate."""

bind = "0.0.0.0:8188"
workers = 1
threads = 4
certfile = "/etc/idlab/tls.crt"
keyfile = "/etc/idlab/tls.key"
# Access log through accesslog.py: tokens in a query string are masked. The
# Authorization header is never logged.
accesslog = "-"
logger_class = "accesslog.MaskingLogger"
