import base64
import json
import os
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from waitress import serve

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "")

DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"
EVENT_WINDOW_DAYS = 7
TOKEN_MAX_AGE_SECONDS = 8 * 60 * 60


class IntegrationError(Exception):
    pass


def integration_settings() -> dict[str, str]:
    settings = {
        "ldaps_url": os.getenv("AD_LDAPS_URL", "").strip(),
        "base_dn": os.getenv("AD_BASE_DN", "").strip(),
        "domain": os.getenv("AD_DOMAIN", "").strip(),
        "netbios_domain": os.getenv("AD_NETBIOS_DOMAIN", "").strip(),
        "upn_suffix": os.getenv("AD_UPN_SUFFIX", "").strip(),
        "allowed_group_dn": os.getenv("AD_ALLOWED_GROUP_DN", "").strip(),
        "service_account": os.getenv("AD_SERVICE_ACCOUNT", "").strip(),
        "service_password": os.getenv("AD_SERVICE_PASSWORD", ""),
        "remote_username": os.getenv("REMOTE_USERNAME", "").strip(),
        "remote_password": os.getenv("REMOTE_PASSWORD", ""),
    }
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise IntegrationError("Set SECRET_KEY to a random value of at least 32 characters.")
    missing = [name for name, value in settings.items() if not value]
    if missing:
        raise IntegrationError("Server integration settings are incomplete.")
    if not settings["ldaps_url"].lower().startswith("ldaps://"):
        raise IntegrationError("AD_LDAPS_URL must use LDAPS (ldaps://).")
    return settings


def token_serializer() -> URLSafeTimedSerializer:
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise IntegrationError("Server authentication is not configured.")
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="defender-sentinel-session")


def accepted_domains(settings: dict[str, str]) -> set[str]:
    return {settings["domain"].casefold(), settings["netbios_domain"].casefold()}


def authenticate_ad(domain: str, username: str, password: str) -> str:
    settings = integration_settings()
    if domain.casefold() not in accepted_domains(settings) or not username or not password:
        return ""
    account = username
    if "\\" in account:
        username_domain, account = account.split("\\", 1)
        if username_domain.casefold() not in accepted_domains(settings):
            return ""
    principal = account if "@" in account else f"{account}@{settings['upn_suffix']}"
    server = Server(
        settings["ldaps_url"],
        use_ssl=True,
        tls=Tls(validate=ssl.CERT_REQUIRED),
        connect_timeout=8,
    )
    connection = Connection(server, user=principal, password=password, auto_bind=False, receive_timeout=8)
    try:
        connection.open()
        if connection.bind():
            if not is_authorized_ad_user(settings, principal):
                return ""
            return f"{settings['netbios_domain']}\\{account.split('@', 1)[0]}"
        if connection.result.get("result") == 49:
            return ""
        raise IntegrationError("The Active Directory authentication service is unavailable.")
    except LDAPException as error:
        raise IntegrationError("The Active Directory authentication service is unavailable.") from error
    finally:
        if connection.closed is False:
            connection.unbind()


def is_authorized_ad_user(settings: dict[str, str], principal: str) -> bool:
    connection = directory_connection(settings)
    user_filter = escape_filter_chars(principal)
    group_filter = escape_filter_chars(settings["allowed_group_dn"])
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        f"(userPrincipalName={user_filter})"
        f"(memberOf:1.2.840.113556.1.4.1941:={group_filter}))"
    )
    try:
        return connection.search(
            search_base=settings["base_dn"],
            search_filter=search_filter,
            search_scope="SUBTREE",
            attributes=["distinguishedName"],
            size_limit=1,
        ) and bool(connection.entries)
    except LDAPException as error:
        raise IntegrationError("Unable to verify Active Directory group membership.") from error
    finally:
        connection.unbind()


def directory_connection(settings: dict[str, str]) -> Connection:
    server = Server(
        settings["ldaps_url"],
        use_ssl=True,
        tls=Tls(validate=ssl.CERT_REQUIRED),
        connect_timeout=8,
    )
    try:
        return Connection(
            server,
            user=settings["service_account"],
            password=settings["service_password"],
            auto_bind=True,
            receive_timeout=15,
        )
    except LDAPException as error:
        raise IntegrationError("Unable to query Active Directory over LDAPS.") from error


def get_ad_computers(settings: dict[str, str]) -> list[dict[str, str]]:
    connection = directory_connection(settings)
    computers = []
    try:
        entries = connection.extend.standard.paged_search(
            search_base=settings["base_dn"],
            search_filter="(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(dNSHostName=*))",
            search_scope="SUBTREE",
            attributes=["dNSHostName", "operatingSystem", "lastLogonTimestamp"],
            paged_size=1000,
            generator=True,
        )
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            attributes = entry.get("attributes", {})
            hostname = attributes.get("dNSHostName")
            if not hostname:
                continue
            if isinstance(hostname, list):
                hostname = hostname[0]
            operating_system = attributes.get("operatingSystem") or ""
            if isinstance(operating_system, list):
                operating_system = operating_system[0]
            computers.append({
                "name": hostname.split(".", 1)[0],
                "hostname": hostname,
                "domain": settings["domain"],
                "os": operating_system,
            })
    except LDAPException as error:
        raise IntegrationError("Unable to read computer objects from Active Directory.") from error
    finally:
        connection.unbind()
    return computers


def run_powershell(script: str, timeout: int = 180, environment: dict[str, str] | None = None) -> str:
    encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    executable = os.getenv("POWERSHELL_PATH", "powershell.exe")
    try:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, **(environment or {})},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IntegrationError("PowerShell remoting could not complete. Check the server and WinRM configuration.") from error
    if result.returncode != 0:
        app.logger.error("PowerShell integration failed: %s", result.stderr[-2000:])
        raise IntegrationError("PowerShell remoting failed. Check WinRM, credentials, and endpoint permissions.")
    return result.stdout.strip()


def collect_defender_data(computers: list[dict[str, str]], settings: dict[str, str]) -> dict[str, dict[str, Any]]:
    hostnames = [computer["hostname"] for computer in computers]
    hosts_json = json.dumps(hostnames)
    hosts_encoded = base64.b64encode(hosts_json.encode("utf-8")).decode("ascii")
    script = r'''
$ErrorActionPreference = 'Stop'
$ComputerNames = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__HOSTS__')) | ConvertFrom-Json
$SecurePassword = ConvertTo-SecureString $env:REMOTE_PASSWORD -AsPlainText -Force
$Credential = [Management.Automation.PSCredential]::new($env:REMOTE_USERNAME, $SecurePassword)
$StartTime = (Get-Date).ToUniversalTime().AddDays(-7)
$Results = Invoke-Command -ComputerName $ComputerNames -Credential $Credential -ThrottleLimit 32 -ErrorAction SilentlyContinue -ScriptBlock {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116,1117,1118,1119,1006,1007; StartTime = $using:StartTime } -MaxEvents 100 -ErrorAction SilentlyContinue
    [pscustomobject]@{
        host = $env:COMPUTERNAME
        antivirusEnabled = [bool]$defender.AntivirusEnabled
        realTimeProtectionEnabled = [bool]$defender.RealTimeProtectionEnabled
        serviceEnabled = [bool]$defender.AMServiceEnabled
        events = @($events | ForEach-Object {
            [pscustomobject]@{
                recordId = $_.RecordId
                eventId = $_.Id
                timestamp = $_.TimeCreated.ToUniversalTime().ToString('o')
                user = $_.UserId.Value
                message = $_.Message
            }
        })
    }
}
ConvertTo-Json -InputObject @($Results) -Depth 5 -Compress
'''.replace("__HOSTS__", hosts_encoded)
    output = run_powershell(script, environment={
        "REMOTE_USERNAME": settings["remote_username"],
        "REMOTE_PASSWORD": settings["remote_password"],
    })
    if not output:
        return {}
    try:
        records = json.loads(output)
    except json.JSONDecodeError as error:
        raise IntegrationError("PowerShell returned data that could not be parsed.") from error
    return {str(record["host"]).split(".", 1)[0].casefold(): record for record in records if record and record.get("host")}


def event_to_alert(computer: dict[str, str], event: dict[str, Any]) -> dict[str, Any]:
    event_id = int(event.get("eventId", 0))
    severity = "critical" if event_id == 1119 else "high" if event_id in (1116, 1118, 1006) else "medium"
    message = str(event.get("message") or "").strip()
    title = message.splitlines()[0][:180] if message else f"Windows Defender event {event_id}"
    status = "Action taken" if event_id in (1117, 1007) else "Action failed" if event_id in (1118, 1119) else "Detection recorded"
    timestamp = str(event.get("timestamp") or "")
    record_id = str(event.get("recordId") or event_id)
    return {
        "id": f"{computer['name']}-{record_id}",
        "severity": severity,
        "title": title,
        "computer": computer["name"],
        "timestamp": timestamp,
        "category": f"Defender event {event_id}",
        "file": "",
        "status": status,
        "user": str(event.get("user") or ""),
        "detectionSource": DEFENDER_LOG,
        "details": {"eventId": event_id, "message": message},
        "logs": [{"type": "danger" if severity == "critical" else "warning", "title": title, "time": timestamp}],
    }


def get_dashboard_payload() -> dict[str, Any]:
    settings = integration_settings()
    computers = get_ad_computers(settings)
    telemetry = collect_defender_data(computers, settings)
    alerts = []
    now = datetime.now(timezone.utc)
    for computer in computers:
        record = telemetry.get(computer["name"].casefold())
        events = record.get("events", []) if record else []
        alerts.extend(event_to_alert(computer, event) for event in events)
        if not record:
            computer.update({"status": "unknown", "alerts": len(events), "lastSeen": "No response"})
        elif not record.get("serviceEnabled") or not record.get("antivirusEnabled"):
            computer.update({"status": "critical", "alerts": len(events), "lastSeen": "Collected just now"})
        elif any(alert["severity"] == "critical" for alert in alerts if alert["computer"] == computer["name"]):
            computer.update({"status": "critical", "alerts": len(events), "lastSeen": "Collected just now"})
        elif not record.get("realTimeProtectionEnabled") or any(
            alert["severity"] == "high" for alert in alerts if alert["computer"] == computer["name"]
        ):
            computer.update({"status": "warning", "alerts": len(events), "lastSeen": "Collected just now"})
        else:
            computer.update({"status": "healthy", "alerts": len(events), "lastSeen": "Collected just now"})
    alerts.sort(key=lambda alert: alert["timestamp"], reverse=True)
    critical_count = sum(alert["severity"] == "critical" for alert in alerts)
    reporting_count = sum(computer["status"] != "unknown" for computer in computers)
    return {
        "stats": [
            {"label": "Defender alerts (7 days)", "value": len(alerts), "change": "observed", "trend": "flat"},
            {"label": "AD computers", "value": len(computers), "change": "discovered", "trend": "flat"},
            {"label": "Reporting endpoints", "value": reporting_count, "change": "responded", "trend": "flat"},
            {"label": "Critical events", "value": critical_count, "change": "in window", "trend": "flat"},
        ],
        "computers": computers,
        "alerts": alerts,
        "collectedAt": now.isoformat(),
    }


def authenticated_user() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    try:
        claims = token_serializer().loads(auth_header.split(" ", 1)[1], max_age=TOKEN_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired, IntegrationError):
        return None
    return claims.get("user") if isinstance(claims, dict) else None


@app.route("/")
def index():
    return send_file("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "defender-sentinel"})


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).strip()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not domain or not username or not password:
        return jsonify({"error": "Domain, username, and password are required."}), 400
    try:
        user = authenticate_ad(domain, username, password)
        if not user:
            return jsonify({"error": "Active Directory rejected these credentials."}), 401
        token = token_serializer().dumps({"user": user})
        return jsonify({"token": token, "user": user})
    except IntegrationError as error:
        app.logger.warning("AD login unavailable: %s", error)
        return jsonify({"error": str(error)}), 503


@app.route("/api/dashboard")
def dashboard():
    if not authenticated_user():
        return jsonify({"error": "Authentication required or session expired."}), 401
    try:
        return jsonify(get_dashboard_payload())
    except IntegrationError as error:
        app.logger.error("Dashboard collection failed: %s", error)
        return jsonify({"error": str(error)}), 503


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    if not authenticated_user():
        return jsonify({"error": "Authentication required or session expired."}), 401
    payload = request.get_json(silent=True) or {}
    computer_name = str(payload.get("computer") or "").strip()
    if not computer_name:
        return jsonify({"error": "Computer name is required."}), 400
    try:
        settings = integration_settings()
        computers = get_ad_computers(settings)
        computer = next((item for item in computers if item["name"].casefold() == computer_name.casefold()), None)
        if not computer:
            return jsonify({"error": "Computer was not found in Active Directory."}), 404
        hosts_encoded = base64.b64encode(json.dumps(computer["hostname"]).encode("utf-8")).decode("ascii")
        script = r'''
$ComputerName = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__HOST__')) | ConvertFrom-Json
$SecurePassword = ConvertTo-SecureString $env:REMOTE_PASSWORD -AsPlainText -Force
$Credential = [Management.Automation.PSCredential]::new($env:REMOTE_USERNAME, $SecurePassword)
$result = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock {
    Start-MpScan -ScanType Quick -ErrorAction Stop
    [pscustomobject]@{ computer = $env:COMPUTERNAME; status = 'started'; scanType = 'quick' }
}
ConvertTo-Json -InputObject $result -Compress
'''.replace("__HOST__", hosts_encoded)
        output = run_powershell(script, timeout=60, environment={
            "REMOTE_USERNAME": settings["remote_username"],
            "REMOTE_PASSWORD": settings["remote_password"],
        })
        result = json.loads(output)
        return jsonify({"status": result["status"], "computer": computer["name"], "scanType": result["scanType"], "message": f"Quick scan started on {computer['name']}"})
    except (IntegrationError, json.JSONDecodeError, KeyError, TypeError) as error:
        message = str(error) if isinstance(error, IntegrationError) else "Remote scan did not return a valid result."
        app.logger.error("Remote scan failed: %s", message)
        return jsonify({"error": message}), 503


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    serve(app, host=host, port=port, threads=16)