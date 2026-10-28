# SENTINEL
### Hardened Linux AI Incident Analyst

**Build the AI. Secure the Linux environment beneath it. Prove that it can recover.**

SENTINEL is a **security-hardened Ubuntu reference implementation** combining real Linux telemetry, deterministic incident detection, separately validated structured AI analysis, least-privilege service execution, and **verified automatic recovery after a controlled process failure**.

We did not stop at a working AI incident dashboard. We hardened the operating environment, tested the security boundaries, deliberately terminated the restricted service process, and verified that systemd recovered it.

> **Scope:** This is a tested local reference implementation—not a production-hardened enterprise service. The dashboard is read-only; its displayed AI assessment is a **labeled synthetic demonstration**, not an automatic diagnosis of live host events. One separate OpenAI API request was successfully validated using **synthetic evidence only**.

## The engineering proof

| Control | Verified observation |
|---|---|
| **SSH hardening** | ED25519 key-based access succeeded; password-only access rejected; root SSH login prohibited |
| **Network boundary** | UFW active, default-deny incoming, with TCP/22 allowed from the trusted LAN |
| **Least privilege** | Dedicated `sentinel` system user; no login shell or sudo permissions |
| **Service isolation** | Root-owned application staging, independent Python environment, hardened systemd test unit |
| **Controlled recovery** | Process `6216` killed → systemd restarted once → process `6488` responded with **HTTP 200** |
| **Software validation** | **29 automated tests passed**; one structured live OpenAI call validated with **synthetic** input |

**Tested October 28, 2026, on Ubuntu Server running in VirtualBox.** The facts above describe the observed test environment; they are not availability guarantees.

---

## 01 · The vision

![SENTINEL Linux AI Incident Analyst — original concept poster](docs/images/Linux-Sentinel-Dashboard.png)

*Original **concept illustration** showing the intended product experience. The screens, commands, and actions depicted in this artwork are **not** presented as verified SENTINEL runtime evidence; the implemented dashboard does not perform autonomous remediation.*

## 02 · What we actually built

SENTINEL reads local Ubuntu journal entries, normalizes telemetry, applies deterministic detection rules, groups candidate conditions, and displays Linux health information in a read-only Streamlit console.

![Real SENTINEL Ubuntu operations console](01-Sentinel-png.png)

*Authentic local operations-dashboard screenshot. CPU load is the 1-minute Linux load average—not CPU utilization. No matches in a sampled window does not imply a detector malfunction.*

**Implemented boundary:** local observation → deterministic matching → candidate-condition presentation. Detection does not establish a root cause or authorize any action.

### Detection and AI assessment

![SENTINEL supplemental detection and assessment visual](docs/images/02-Sentinel.png)

*Supplementary project visual; not independently sufficient to verify a live AI diagnosis or autonomous response.*

A separate real dashboard observation examined **180 journal records** and produced **one service-failure rule match** and **one grouped candidate condition**. The adjacent AI panel showed a **synthetic fixture**, explicitly labeled as such, with evidence reference `E001`, approved runbook `RB-SERVICE`, and an uncertainty statement: *root cause not established*.

A separately invoked OpenAI adapter completed **one live API request with synthetic evidence** and validated the structured result. The dashboard itself makes **no automatic API requests**.

## 03 · How we hardened the host and runtime

![SENTINEL architecture and security boundaries](docs/images/sentinel-architecture.svg)

*Explanatory architecture illustration; the verified configuration and command results are described below.*

### Hardening visual

![SENTINEL supporting engineering visual 03](docs/images/Sentinel-03.png)

*Supporting project visual. Refer to the tested controls below for authoritative implementation evidence; visual design alone does not establish a security property.*

**Verified controls:**

1. **SSH:** Public-key authentication enabled; password and keyboard-interactive SSH logins disabled; root SSH login disabled. A new key-only connection succeeded, and a password-only connection was rejected.
2. **Firewall:** UFW enabled with **deny incoming / allow outgoing**. TCP/22 was allowed from the trusted `192.168.1.0/24` LAN. Network access and application accessibility were retested after activation.
3. **Dashboard access:** The web service listened on `127.0.0.1`, with browser access forwarded through an encrypted SSH tunnel. No direct inbound Streamlit firewall exception was required.
4. **Service identity:** The `sentinel` account uses `/usr/sbin/nologin`, has no sudo permissions, and was granted `systemd-journal` group membership to read relevant system records.
5. **Systemd isolation:** A separate deployment under `/opt/sentinel` uses root-owned application code, an independent Python 3.14.4 / Streamlit 1.66.1 environment, and service controls including `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, capability restrictions, and resource ceilings.
6. **Credential separation:** The isolated dashboard was not given the OpenAI API key, the developer's SSH credentials, or the existing development SQLite database.

The restricted test service ran on **`127.0.0.1:8503`**, independently of the original dashboard on **`127.0.0.1:8501`**.

**Threat-model note:** `systemd-journal` membership grants broad journal access, and the trusted-LAN UFW rule permits SSH connectivity from any address in that subnet; SSH authentication is still required. These are deliberate, documented boundaries—not claims of complete least privilege across every source or network segment.

## 04 · How we proved recovery

![SENTINEL — controlled failure and automatic restart summary](docs/images/06-Sentinel.png)

*Presentation summary derived from the verified systemd journal and post-recovery health check—not a raw log screenshot and not an end-to-end availability SLA.*

| Time (UTC, October 28) | Recorded event |
|---|---|
| **16:45:01** | Controlled `SIGKILL` terminated the restricted service's main process, PID **6216** |
| **16:45:01** | systemd recorded `status=9/KILL` and service result `signal` |
| **16:45:04** | systemd scheduled the automatic restart; restart counter reached **1** |
| **16:45:05** | Replacement PID **6488** reported its web server listening on `127.0.0.1:8503` |
| **Post-recovery check** | `active`, `MainPID=6488`, `NRestarts=1`, and **HTTP 200** from the health endpoint |

The time from the failure signal to the replacement server's startup log was **approximately 4.5 seconds**. This is a measured **process restart interval**, **not** an end-to-end recovery SLA.

The original development dashboard remained listening on `127.0.0.1:8501` during this test.

### Verify the service on a provisioned Ubuntu host

```bash
systemctl show sentinel-test.service -p User -p Group -p MainPID -p NRestarts
curl --max-time 5 -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  http://127.0.0.1:8503/_stcore/health
sudo journalctl -u sentinel-test.service -n 20 --no-pager
```

These are **inspection commands**; they do not trigger a new failure. The tested systemd configuration is preserved at [docs/deployment/sentinel-test.service](docs/deployment/sentinel-test.service).

## 05 · Run the development dashboard

On a Linux host with appropriate access to system journal records and Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'streamlit==1.66.1'
python -m unittest discover -s tests -v
python -m streamlit run app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --server.headless true
```

From a second workstation, create an SSH tunnel using authorized credentials:

```bash
ssh -N -L 8502:127.0.0.1:8501 YOUR_USER@YOUR_HOST
```

Open `http://127.0.0.1:8502` in a local browser.

The [systemd unit](docs/deployment/sentinel-test.service) is a **reference to a tested, manually started restricted deployment**. It assumes that `/opt/sentinel`, the required Python dependencies, the non-sudo `sentinel` service identity, and journal permissions have already been provisioned. It is **not** automatically installed or enabled by cloning this repository.

## Limitations and validation boundaries

- **Reference implementation, not an enterprise production deployment.** The test service was named `sentinel-test.service` and **was not enabled at boot**.
- No full-reboot recovery, load testing, fleet-scale behavior, adversarial security assessment, enterprise identity integration, or end-to-end availability validation was performed.
- The dashboard's AI assessment is a **synthetic fixture**. The separate live OpenAI call used **synthetic evidence**, not live Ubuntu logs.
- Structured output validation checks shape and approved references; it does not independently prove factual accuracy or root cause.
- Regex-based redaction is not a comprehensive guarantee against sensitive data disclosure.
- The service's `systemd-journal` membership provides broad log access, not per-event fine-grained authorization.
- Ubuntu had pending package/security updates during the validation session.
- Illustrations and supplemental visuals explain concepts; **documented commands, journal entries, and tests** establish verified system behavior.

---

> **Capability is not authority.** Detection, model interpretation, human approval, and execution are separate concerns.

**Build it. Secure it. Test it. Prove it.**
