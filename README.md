# Cyberstack Tools

Small scripts for [Cyberstack](https://github.com/cyberstack). Defensive and operational only.

Python scripts use the standard library. No extra packages.

## Contents

| Script | What it does |
| --- | --- |
| [`host_posture.py`](#host_posturepy) | Read-only DNS, TLS cert, and a few HTTPS headers for one hostname |
| [`dp_install.sh`](#dp_installsh) | Install Docker and Portainer on a new Linux host |

---

## host_posture.py

Shows what a hostname **publishes**:

- DNS: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`
- Mail: `SPF` from TXT, `DMARC` from `_dmarc.<name>`
- TLS certificate on port 443 (expiry, SAN, issuer)
- HTTPS headers: HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`

It only queries the name you pass (plus `_dmarc.<name>`). It does not scan extra ports or send payloads.

**Needs:** Python 3.8+

```bash
python3 host_posture.py example.com
python3 host_posture.py example.com --timeout 8
```

---

## dp_install.sh

Installs Docker Engine (`docker.io`) and Portainer CE on a Debian/Ubuntu host. After it finishes, open Portainer at `http://<host>:9000`.

**Needs:** root on Debian or Ubuntu, outbound HTTPS for the Portainer image.

```bash
sudo bash dp_install.sh
```

### Proxmox VM

Enable nesting **before** you run it:

1. Select the VM
2. **Options → Features → Edit**
3. Tick **Nesting** → OK
