# OpenSSH Server Installer for dstack
# Multi-stage build for fully static OpenSSH

FROM alpine:latest AS builder

RUN apk add --no-cache \
    build-base \
    linux-headers \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    wget

WORKDIR /build

# Download and build OpenSSH fully static
ARG OPENSSH_VERSION=9.9p1
RUN wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz && \
    tar xzf openssh-${OPENSSH_VERSION}.tar.gz && \
    cd openssh-${OPENSSH_VERSION} && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc/ssh \
        --with-privsep-path=/run/sshd \
        --without-pam \
        --without-selinux \
        --without-kerberos5 \
        --without-libedit \
        LDFLAGS="-static" \
        LIBS="-lcrypto -lz -lpthread" && \
    make -j$(nproc) && \
    make install DESTDIR=/build/install && \
    strip /build/install/usr/sbin/sshd \
          /build/install/usr/bin/ssh \
          /build/install/usr/bin/ssh-keygen \
          /build/install/usr/bin/scp \
          /build/install/usr/bin/sftp \
          /build/install/usr/libexec/sftp-server \
          /build/install/usr/libexec/sshd-session

# Verify static linking
RUN echo "Binary type:" && \
    file /build/install/usr/sbin/sshd && \
    file /build/install/usr/sbin/sshd | grep -q "static" && \
    echo "✓ sshd is statically linked"

# Final image
FROM alpine:latest

RUN apk add --no-cache bash wget ca-certificates

# Copy static binaries from builder
COPY --from=builder /build/install/usr/sbin/sshd /usr/sbin/sshd
COPY --from=builder /build/install/usr/bin/ssh /usr/bin/ssh
COPY --from=builder /build/install/usr/bin/ssh-keygen /usr/bin/ssh-keygen
COPY --from=builder /build/install/usr/bin/scp /usr/bin/scp
COPY --from=builder /build/install/usr/bin/sftp /usr/bin/sftp
COPY --from=builder /build/install/usr/libexec/sftp-server /usr/lib/openssh/sftp-server
COPY --from=builder /build/install/usr/libexec/sshd-session /usr/libexec/sshd-session

# Copy install scripts
COPY scripts/install-openssh.sh /usr/local/bin/install-openssh.sh
COPY scripts/mount-overlay.sh /usr/local/bin/mount-overlay.sh

RUN chmod +x /usr/local/bin/* /usr/sbin/sshd /usr/bin/ssh /usr/bin/ssh-keygen \
    /usr/bin/scp /usr/bin/sftp /usr/lib/openssh/sftp-server /usr/libexec/sshd-session

# Build metadata
ARG DSTACK_REV

RUN echo "OpenSSH Server Installer Image (Static Build)" > /usr/local/share/BUILD_INFO && \
    echo "Built: $(date)" >> /usr/local/share/BUILD_INFO && \
    echo "OpenSSH: $(/usr/bin/ssh -V 2>&1)" >> /usr/local/share/BUILD_INFO && \
    echo "Git Revision: ${DSTACK_REV:-unknown}" >> /usr/local/share/BUILD_INFO

WORKDIR /workspace

CMD ["/usr/local/bin/install-openssh.sh"]
