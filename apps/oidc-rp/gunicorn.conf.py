"""Gunicorn settings for the OIDC RP.

HTTPS with the lab certificate, except where OIDC_RP_TLS=off: oidc-rp-edge
sits behind the reverse proxy, which ends TLS and talks plain HTTP to it.
"""

import os

bind = "0.0.0.0:8182"
workers = 1
threads = 4
# Access log through accesslog.py: one-time login values are masked.
accesslog = "-"
logger_class = "accesslog.MaskingLogger"
if os.environ.get("OIDC_RP_TLS", "on") != "off":
    certfile = "/etc/idlab/tls.crt"
    keyfile = "/etc/idlab/tls.key"
