ISTRUZIONI ALL’INSTALLAZIONE DELL’APPLICATIVO EDR/XDR

Requisiti:

- Docker Desktop (Windows/macOS) oppure Docker Engine (Linux)

- Git

- Ambiente Bash (Linux/macOS) oppure Git Bash o WSL su Windows

- .NET SDK (necessario per l’avvio della dashboard)

Verificare l’installazione con: docker --version docker compose version git --version

1 - Clonare la repository in locale: git clone https://github.com/JumanJuJ/XDR_PROJECT_CHIUSSI.git cd

2 - Assicurarsi che Docker Engine sia attivo: docker info

3 - Navigare nella directory in cui si trova il file docker-compose: cd Docker

4 - Avviare i container tramite Docker Compose:

Modalità standard: docker compose up --build

Modalità testing: docker compose --profile test -f docker-compose.yaml -f docker-compose.test.yaml up --build

5 - Visualizzare i report generati automaticamente nel percorso: Docker/tests/report

ISTRUZIONI ALL’AVVIO DELLA DASHBOARD WEB

1 - Assicurarsi che la porta 7140 sia libera.

Su Linux/macOS: lsof -i :7140

Su Windows: netstat -ano | findstr 7140

2 - Sincronizzare i dati locali verso il database cloud per consentire la visualizzazione aggiornata della dashboard.

Posizionarsi nella cartella Docker ed eseguire:

Su Linux/macOS: ./convert.sh

Su Windows (Git Bash o WSL): bash convert.sh

Nota: Se si utilizza PowerShell, è necessario eseguire lo script tramite Git Bash o WSL.

3 - Avviare il server della dashboard.

Posizionarsi nel percorso: XDR-DashBoard/DashboardServer

Eseguire: dotnet run

4 - Visualizzare la dashboard web all’indirizzo: https://localhost:7140
