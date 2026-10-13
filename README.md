# Defender Sentinel

A Windows-hosted dashboard that authenticates users against Active Directory over LDAPS, discovers enabled computer accounts, reads Microsoft Defender Operational events and status through PowerShell remoting, and can start a remote quick scan.

## Features

- Dark blue enterprise security aesthetic
- Live AD computer discovery
- Defender health and Operational event collection
- Searchable endpoint and event views
- Remote quick scans through PowerShell remoting
- Signed, expiring application sessions

No demo accounts, sample endpoints, canned alerts, or simulated scan responses are included. The dashboard remains unavailable until its real directory and endpoint integrations are configured.

## Configure on Windows Server

1. Use a domain-joined, supported Windows Server with trusted LDAPS connectivity to a domain controller.
2. Install Python 3.12 or newer and copy `.env.example` to `.env` with `Copy-Item .env.example .env`.
3. Set every value in `.env`. Use the actual domain FQDN, NetBIOS name, UPN suffix, base DN, LDAPS URL, an AD security-group DN authorized to use the dashboard, a read-only AD service account, and a dedicated remote-management account. Generate a unique `SECRET_KEY` of at least 32 characters.
4. Restrict `.env` file permissions to the application service identity. Never commit it or expose it to the browser.
5. Install and configure WinRM / PowerShell remoting on managed endpoints. The remote account needs permission to read the Defender status and event log and to invoke `Start-MpScan`.
6. Install dependencies and start the service:

```powershell
.\run_server.ps1
```

The default listener is `127.0.0.1:8000`, suitable behind an HTTPS reverse proxy. Set `HOST` only when direct network binding is explicitly required. Do not expose the Flask/Waitress listener to untrusted networks.

The dashboard makes a live directory query and remote Defender query when loaded. It reads the last seven days of Defender Operational events. Collection time depends on the number of AD computers and endpoint availability; this initial implementation queries endpoints directly and is intended for a small initial deployment. For larger fleets, use Windows Event Forwarding or the Microsoft Defender for Endpoint API instead of synchronous fan-out.

## Configuration

- `AD_LDAPS_URL`: domain controller URL using `ldaps://` and a trusted certificate.
- `AD_BASE_DN`: directory search root, such as `DC=corp,DC=example,DC=com`.
- `AD_DOMAIN`, `AD_NETBIOS_DOMAIN`, `AD_UPN_SUFFIX`: real AD domain naming values accepted by the login form.
- `AD_ALLOWED_GROUP_DN`: AD group allowed to access the dashboard; nested group membership is checked.
- `AD_SERVICE_ACCOUNT`, `AD_SERVICE_PASSWORD`: read-only directory search identity.
- `REMOTE_USERNAME`, `REMOTE_PASSWORD`: domain identity for WinRM Defender collection and scan actions.
- `SECRET_KEY`: random application signing key, at least 32 characters.

This build does not persist event history or scan audit records. Endpoint status and events are collected from the live domain when the dashboard is requested.
