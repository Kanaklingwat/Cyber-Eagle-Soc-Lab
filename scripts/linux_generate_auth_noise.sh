#!/usr/bin/env bash
set -e
echo "[*] Generating SSH failures (localhost) ..."
for i in {1..7}; do
  ssh wronguser@localhost -o PreferredAuthentications=password -o PubkeyAuthentication=no || true
done
echo "[*] Generating sudo activity ..."
sudo -k; for i in {1..6}; do sudo -l || true; done
echo "[*] Done. Check your SIEM."
