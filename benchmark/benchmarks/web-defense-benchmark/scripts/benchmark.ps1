[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "clean", "status", "logs")]
    [string]$Action = "start",

    [ValidateSet("normal", "vulnerable")]
    [string]$Mode = "normal",

    [string]$Modules = "sql-injection.product-search"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$AppDirectory = Join-Path $ProjectRoot "app"
$ComposeFile = Join-Path $AppDirectory "compose.yaml"

function Invoke-Compose {
    param([string[]]$ComposeArguments)

    & docker compose --project-directory $AppDirectory -f $ComposeFile @ComposeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

switch ($Action) {
    "start" {
        if ($Mode -eq "vulnerable" -and [string]::IsNullOrWhiteSpace($Modules)) {
            throw "-Modules is required in vulnerable mode"
        }

        $PreviousModules = $env:RUBY_WEB_VULNERABILITY_MODULES
        $PreviousTrialId = $env:RUBY_WEB_TRIAL_ID
        try {
            if ($Mode -eq "vulnerable") {
                $env:RUBY_WEB_VULNERABILITY_MODULES = $Modules
                $env:RUBY_WEB_TRIAL_ID = [Guid]::NewGuid().ToString("N")
            }
            else {
                $env:RUBY_WEB_VULNERABILITY_MODULES = ""
                $env:RUBY_WEB_TRIAL_ID = ""
            }
            Invoke-Compose @("up", "-d", "--build", "--wait")
        }
        finally {
            if ($null -eq $PreviousModules) {
                Remove-Item Env:RUBY_WEB_VULNERABILITY_MODULES -ErrorAction SilentlyContinue
            }
            else {
                $env:RUBY_WEB_VULNERABILITY_MODULES = $PreviousModules
            }
            if ($null -eq $PreviousTrialId) {
                Remove-Item Env:RUBY_WEB_TRIAL_ID -ErrorAction SilentlyContinue
            }
            else {
                $env:RUBY_WEB_TRIAL_ID = $PreviousTrialId
            }
        }

        Write-Host "RUBY benchmark is ready at http://127.0.0.1:18080"
        Write-Host "Mode: $Mode"
        if ($Mode -eq "vulnerable") {
            Write-Host "Modules: $Modules"
        }
    }
    "stop" {
        Invoke-Compose @("down")
    }
    "clean" {
        Invoke-Compose @("down", "--volumes", "--remove-orphans")
    }
    "status" {
        Invoke-Compose @("ps")
    }
    "logs" {
        Invoke-Compose @("logs", "--tail", "200")
    }
}
