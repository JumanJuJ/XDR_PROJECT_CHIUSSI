FROM kalilinux/kali-rolling

#RUN apt-get update

WORKDIR /attacks
COPY attacks/ /attacks/
RUN set -eux; \
    for i in 1 2 3 4 5; do \
      apt-get update && break || (echo "apt-get update failed, retry $i..." && sleep 5); \
    done; \
    apt-get install -y --no-install-recommends --fix-missing \
      ca-certificates curl iputils-ping tcpdump iproute2 libpcap0.8 hping3 ettercap-text-only net-tools dsniff; \
    rm -rf /var/lib/apt/lists/*



RUN mkdir -p /attacks/logs \
  && touch /attacks/logs/attacks.log \
  && chmod 644 /attacks/logs/attacks.log
#CMD ["sleep", "infinity"]
