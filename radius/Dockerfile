# FreeRADIUS server for the lab (internal network only). It authenticates
# users against the lab's OpenLDAP directory.
#
# The project's official image, with its stock configuration removed so
# that nothing it ships is live (such as the "testing123" localhost
# client). Only the dictionaries are kept; the files here replace the rest.
FROM freeradius/freeradius-server:3.2.10@sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812
RUN find /etc/freeradius -mindepth 1 -maxdepth 1 ! -name dictionary -exec rm -rf {} + \
 && mkdir -p /etc/freeradius/mods /etc/freeradius/sites
COPY --chmod=0644 radiusd.conf clients.conf /etc/freeradius/
COPY --chmod=0644 mods/always mods/ldap /etc/freeradius/mods/
COPY --chmod=0644 sites/default /etc/freeradius/sites/
# The image's entrypoint runs "freeradius -f" plus these arguments:
# log to stdout so `docker compose logs radius` shows every request.
CMD ["-l", "stdout"]
