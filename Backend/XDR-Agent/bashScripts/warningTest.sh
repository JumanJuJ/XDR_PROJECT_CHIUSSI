#!/bin/bash
set -euo pipefail

rm -rf /bin/xdrtest

sleep 30
PAUSE=2

TESTDIR="/bin/xdrtest"          # matcha IsSuspiciousPath("/tmp")

SRC="$TESTDIR/invoice.pdf.c"
BIN="$TESTDIR/invoice.pdf.bin"  

mkdir -p "$TESTDIR"

echo "[*] Writing C source (benigno: sleep + stringhe IOC)"
cat > "$SRC" <<'EOF'
#include <stdio.h>
#include <unistd.h>

static const char *ioc_url1 = "https://example.com/login";
static const char *ioc_url2 = "http://198.51.100.10/update";     // IP nel testo + URL
static const char *ioc_ip1  = "8.8.8.8";
static const char *ioc_ip2  = "1.1.1.1";

int main(void) {
    // Non fa nulla di male: stampa due righe e dorme
    printf("hello xdr test\n");
    printf("ioc: %s %s %s %s\n", ioc_url1, ioc_url2, ioc_ip1, ioc_ip2);

    // tieni vivo il processo per permettere allo snapshot processi di beccarlo
    sleep(600);
    return 0;
}
EOF

echo "[*] Compiling benign ELF"
if command -v gcc >/dev/null 2>&1; then
  gcc -O0 -g "$SRC" -o "$BIN"
elif command -v cc >/dev/null 2>&1; then
  cc -O0 -g "$SRC" -o "$BIN"
else
  echo "ERROR: no C compiler found (gcc/cc missing)" >&2
  exit 1
fi

echo "[*] Setting permissions"
chmod 644 "$BIN"
sleep 30

echo "[*] Making executable (chmod +x) and running"
chmod +x "$BIN"
sleep "$PAUSE"

"$BIN" >/dev/null 2>&1 &
echo "[*] Started $BIN with PID $!"

echo "[*] Done. Your agent should detect first-seen execution + suspicious path + IOCs in strings."

