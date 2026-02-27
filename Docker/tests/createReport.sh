#!/bin/bash
set -e
sleep 20


# ------- ARP SPOOFING --------
REPORT_DIR="/tests/report"
mkdir -p "$REPORT_DIR"

#docker exec -t mongo mongosh --quiet -u root -p example --authenticationDatabase admin --eval "db.getSiblingDB('XDR-Db').incidentReportArpSpoof.find().sort({date:-1}).limit(5).forEach(printjson)" > "$REPORT_DIR"
mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .incidentReportArpSpoof
      .find()
      .sort({date:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "ARP_SPOOFING",
      timestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_ARP_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

# ------------ SYN FLOOD DOS -----------
mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .incidentReport
      .find({attackType: "Dos"})
      .sort({date:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "DOS",
      timestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_DOS_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

# ------------- SYN FLOOD DDOS ---------------
mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .incidentReport
      .find({attackType: "DDos"})
      .sort({date:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "DDOS",
      timestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_DDOS_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

#------------------- PRIVILEGE ESCALATION --------------
mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .localIncidentReport
      .find()
      .sort({updatedAtUtc:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "LOCAL_MENACE",
      timestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_PRIV_ESC_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

#-------------------- LOCAL WARNINGS -------------------
mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .incidentReport
      .find()
      .sort({date:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "LOCAL_WARNING",
      TimestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_WARNING_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

#------------------ MALWARE ------------------------

mongosh --quiet \
  "mongodb://root:example@mongo:27017/?authSource=admin" \
  --eval '
    const docs = db.getSiblingDB("XDR-Db")
      .incidentReport
      .find()
      .sort({Timestamp:-1})
      .limit(5)
      .toArray();

    print(JSON.stringify({
      testType: "MALWARE",
      TimestampUtc: new Date().toISOString(),
      count: docs.length,
      incidents: docs
    }, null, 2));
  ' > "$REPORT_DIR/report_MALWARE_$(date -u +%Y%m%dT%H%M%SZ).json"

echo "[OK] Report generated"

#---------------- RESPONSES----------------------

TS="$(date -u +%Y%m%dT%H%M%SZ)"
MENACE_TYPES=("arp_spoofing" "syn_flood" "dos" "ddos" "privilege_escalation" "malware")

for MENACE in "${MENACE_TYPES[@]}"; do
  mongosh --quiet \
    "mongodb://root:example@mongo:27017/?authSource=admin" \
    --eval "
      const doc = db.getSiblingDB('XDR-Db')
        .Response
        .find({ menace_type: '${MENACE}' })
        .sort({ date: -1 })
        .limit(1)
        .toArray();

      print(JSON.stringify({
        menace_type: '${MENACE}',
        timestampUtc: new Date().toISOString(),
        count: doc.length,
        response: doc.length ? doc[0] : null
      }, null, 2));
    " > "$REPORT_DIR/response_${MENACE}_${TS}.json"

  echo "[OK] Response report generated for $MENACE"
done


