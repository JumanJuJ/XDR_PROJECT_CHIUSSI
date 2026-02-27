FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# 1) Copio il csproj nella struttura giusta
COPY Backend/XDR-Manager/server/server.csproj XDR-Manager/server/
COPY Backend/XDR-Manager/XDR-Classes/ XDR-Manager/XDR-Classes/
COPY Backend/XDR-Manager/XDR-Detection/ XDR-Manager/XDR-Detection/
COPY Backend/XDR-Manager/services/ XDR-Manager/services/
COPY Backend/XDR-Manager/XDR-Response/ XDR-Manager/XDR-Response/
COPY Backend/XDR-Manager/bashScripts XDR-Manager/bashScripts
COPY Backend/XDR-Manager/ErrorHandler XDR-Manager/ErrorHandler

# 2) Vado nella cartella del progetto
WORKDIR /src/XDR-Manager/server
RUN dotnet restore

# 3) Copio il resto dei sorgenti
COPY Backend/XDR-Manager/server/ .
#COPY Backend/XDR-Manager/XDR-Detection/  XDR-Manager/XDR-Detection

# 4) Pubblico
RUN dotnet publish -c Release -o /out

# ------------- RUNTIME -------------
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

COPY --from=build /out /app/server
COPY Backend/XDR-Manager/XDR-Detection XDR-Manager/XDR-Detection
COPY Backend/XDR-Manager/bashScripts XDR-Manager/bashScripts


RUN apt-get update && \
    apt-get install -y \
    curl \
    netcat-openbsd \
    file

RUN mkdir -p /app/serverData/logs
RUN mkdir -p /app/detectionData/logs
#RUN chmod +x /XDR-Manager/bashScripts/*
#ENV ASPNETCORE_URLS=http://+:8080
#ENV SERVER_LOG_PATH=/app/serverData/logs
#ENV DETECTION_LOG_PATH=/app/detectionData/logs
#ENV XDR_MANAGER_SCRIPT_PATH=/app/XDR-Manager/bashScripts
EXPOSE 8080


ENTRYPOINT ["dotnet", "/app/server/server.dll"]

