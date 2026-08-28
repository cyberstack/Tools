# Tools

Small scripts for Cyberstack. Defensive and operational only. No exploit payloads.

#### host_posture.py

Read-only view of what a hostname publishes: A/AAAA/MX/NS/TXT/CAA, the TLS certificate on 443, and a few HTTPS security headers. Recurses only for the name you pass (plus `_dmarc.<name>`). Stdlib Python 3. No extra packages.

```
python3 host_posture.py example.com
python3 host_posture.py example.com --timeout 8
```

#### dp_install.sh - A quick bash script installing Docker and Portainer on a new Linux system.

NOTE:
If you run this in Proxmox on a VM, you must enable Nesting before running the script. Go to Proxmox VM > Options > Features > Edit > Nesting = Enable > OK.
After the install is complete, navigate to your server's <IP>:9000 to access your new Portainer
