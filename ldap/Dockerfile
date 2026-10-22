# OpenLDAP directory for Keycloak user federation (internal network only).
#
# Built from Debian rather than a third-party OpenLDAP image: the widely used
# ones are either OpenLDAP 2.4 and unmaintained, or frozen "legacy" builds.
FROM debian:trixie-20260918-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# DEBIAN_FRONTEND: don't let slapd's postinst ask for an admin password; the
# package's default database is deleted anyway, entrypoint.sh builds its own.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d /var/lib/ldap \
 # The container runs as LAB_UID with group 0 (like Keycloak). A new named
 # volume copies this directory's group and mode, so slapd can write to it.
 && mkdir -p /var/lib/idlab-ldap \
 && chgrp 0 /var/lib/idlab-ldap && chmod 0770 /var/lib/idlab-ldap \
 # ldapwhoami/ldapsearch in this container verify TLS against the lab CA.
 && printf 'TLS_CACERT /etc/idlab/ca.crt\n' >/etc/ldap/ldap.conf
COPY config.ldif seed.ldif /etc/idlab/ldap/
COPY entrypoint.sh /usr/local/bin/ldap-entrypoint.sh
EXPOSE 1636
ENTRYPOINT ["/usr/local/bin/ldap-entrypoint.sh"]
