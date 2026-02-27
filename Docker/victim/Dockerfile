### STAGE 1: BUILD .NET (compilazione)
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

COPY Backend/XDR-Agent/XDR-Agent/XDR-Agent.csproj ./XDR-Agent/
COPY Backend/XDR-Agent/XDR-Agent ./XDR-Agent/
WORKDIR /src/XDR-Agent

RUN dotnet publish -c Release -o /app/published


### STAGE 2: RUNTIME (immagine finale)
FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine

#installazione pacchetti aggiuntivi
RUN apk add --no-cache \
    ca-certificates \
    curl \
    iputils \
    tcpdump \
    libpcap \
    bash \
    netcat-openbsd \
    iproute2 \
    procps \
    net-tools \
    iptables \
    build-base \
    tshark \
    findutils \
    coreutils   \
    build-base   \
    nano   \
    sudo   \
    gcc


RUN mkdir -p /app/XDR-AgentData/bashScripts
RUN mkdir -p /app/XDR-AgentData/logs
RUN mkdir -p /app/XDR-AgentData/captures
RUN adduser -D attacker && adduser attacker wheel
RUN echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers

USER root
WORKDIR /app

COPY --from=build /app/published/ ./XDR-Agent
COPY Backend/XDR-Agent/bashScripts /app/XDR-AgentData/bashScripts  
COPY ../Docker/start.sh /usr/local/bin/start.sh
RUN chmod +x /app/XDR-AgentData/bashScripts/*.sh || true

ENTRYPOINT ["/usr/local/bin/start.sh"]
