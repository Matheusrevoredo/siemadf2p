$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$PythonCmd = Get-Command py -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    throw "Python was not found. Install Python 3.12 or newer before running this server."
}

& $PythonCmd.Source -m pip install -r requirements.txt
if (-not $env:HOST) { $env:HOST = "127.0.0.1" }
if (-not $env:PORT) { $env:PORT = "8000" }

& $PythonCmd.Source app.py
