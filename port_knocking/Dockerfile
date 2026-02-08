# FROM python:3.11-slim

# WORKDIR /app

# RUN apt-get update \
#     && apt-get install -y --no-install-recommends iptables iproute2 netcat-openbsd\
#     && rm -rf /var/lib/apt/lists/*

# COPY knock_server.py knock_client.py ./

# CMD ["python3", "knock_server.py"]
# # CMD nc -l -p 2222 -k -v & python3 knock_server.py
# FROM python:3.11-slim

# WORKDIR /app

# RUN apt-get update \
#     && apt-get install -y --no-install-recommends iptables iproute2 netcat-openbsd knockd \
#     && rm -rf /var/lib/apt/lists/*

# COPY knockd.conf /etc/knockd.conf

# # COPY knock_server.py knock_client.py ./
# CMD systemctl start knockd && systemctl enable knockd && systemctl status knockd
# # CMD ["python3", "knock_server.py"]

# FROM python:3.11-slim

# WORKDIR /app

# RUN apt-get update \
#     && apt-get install -y --no-install-recommends iptables iproute2 netcat-openbsd knockd \
#     && rm -rf /var/lib/apt/lists/*

# COPY knockd.conf /etc/knockd.conf
# COPY knock_server.py knock_client.py ./

# # EXPOSE 2222

# CMD knockd -d && nc -l -p 2222

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 netcat-openbsd knockd \
    && rm -rf /var/lib/apt/lists/*

# Copy knockd configuration
COPY knockd.conf /etc/knockd.conf

# Enable knockd to start and set network interface
RUN echo 'START_KNOCKD=1' > /etc/default/knockd \
    && echo 'KNOCKD_OPTS="-i eth0"' >> /etc/default/knockd

COPY knock_server.py knock_client.py ./

EXPOSE 2222

# Start knockd daemon and then start service on port 2222
CMD knockd -d && nc -l -p 2222