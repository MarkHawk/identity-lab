# The lab's NAS: a RADIUS client, as a switch, wireless controller or VPN
# gateway would be. It runs nas-auth on request (docker compose exec nas
# nas-auth <user>) and keeps its own copy of the shared secret.
#
# Same pinned image as radius/, for its radclient; none of its server
# configuration is used.
FROM freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
# The container runs as LAB_UID with group 0. A new named volume copies this
# directory's group and mode, so the NAS can write its secret there.
RUN mkdir -p /var/lib/nas && chgrp 0 /var/lib/nas && chmod 0770 /var/lib/nas
COPY --chmod=0755 nas-entrypoint.sh /usr/local/bin/nas-entrypoint.sh
COPY --chmod=0755 nas-auth.sh /usr/local/bin/nas-auth
ENTRYPOINT ["/usr/local/bin/nas-entrypoint.sh"]
