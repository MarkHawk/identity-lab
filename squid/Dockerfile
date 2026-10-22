# Squid egress proxy for the lab (internal network only), like a corporate
# forward proxy that servers must use to reach anything outside their network.
#
# Built from the upstream source, not a distribution package: Debian trixie's
# squid 6.13 is still open to advisories that upstream fixed in 7.6 and 7.7
# (SQUID-2026:6 to :9), and Alpine has 7.6. squid-7.7.tar.xz was verified
# against the Squid project's code signing key (29B4 B1F7 CE03 D1B1 DED2
# 2F30 28F8 5029 FEF6 E865) when pinned; ADD --checksum holds it to that file.
# OpenSSL for TLS interception (ssl-bump); features the lab doesn't use are
# left out.
FROM debian:trixie-20260918-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config xz-utils perl \
      libssl-dev libltdl-dev libcap-dev \
 && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:e3bd613b91b1c498ec2992276063342a85cd6edddd5521294e04f44bc055da9b \
    https://github.com/squid-cache/squid/releases/download/SQUID_7_7/squid-7.7.tar.xz /tmp/
# --disable-arch-native: the image must run on any x86_64 CPU, not just the
# one it was built on (CI runners and codespaces differ).
RUN tar -xJf /tmp/squid-7.7.tar.xz -C /tmp \
 && cd /tmp/squid-7.7 \
 && ./configure --prefix=/usr/local/squid --sysconfdir=/etc/squid \
      --localstatedir=/var --with-logdir=/tmp --with-pidfile=/tmp/squid.pid \
      --disable-arch-native --disable-dependency-tracking --disable-strict-error-checking \
      --with-openssl --enable-ssl-crtd \
      --enable-auth-basic=NCSA --disable-auth-digest --disable-auth-negotiate --disable-auth-ntlm \
      --disable-external-acl-helpers --disable-url-rewrite-helpers --disable-storeid-rewrite-helpers \
      --disable-security-cert-validators --disable-log-daemon-helpers \
      --disable-icap-client --disable-ecap --disable-snmp --disable-htcp --disable-wccp \
      --disable-wccpv2 --disable-cache-digests --disable-icmp --disable-delay-pools \
      --disable-eui --disable-translation --disable-auto-locale \
      --without-gnutls --without-mit-krb5 --without-heimdal-krb5 --without-gss \
      --without-libxml2 --without-expat --without-nettle --without-netfilter-conntrack \
      --without-systemd \
 && make -j"$(nproc)" \
 && make install-strip \
 && rm -rf /etc/squid/*.default /etc/squid/squid.conf.documented

FROM debian:trixie-20260918-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# openssl: hashes the proxy password at start. curl: by-hand checks in the runbooks.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libssl3t64 libltdl7 libcap2 \
      openssl curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/squid /usr/local/squid
COPY --from=build /etc/squid /etc/squid
COPY --chmod=0644 squid.conf /etc/squid/squid.conf
COPY --chmod=0755 entrypoint.sh /usr/local/bin/squid-entrypoint.sh
ENV PATH=/usr/local/squid/sbin:/usr/local/squid/bin:$PATH
EXPOSE 3128
ENTRYPOINT ["/usr/local/bin/squid-entrypoint.sh"]
