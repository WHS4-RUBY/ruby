[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("list", "validate", "smoke", "serve")]
    [string]$Action = "list",

    [string]$Condition = "proxy-only",
    [string]$Registry = "",
    [string]$RequestPath = "/normal",
    [int]$ExpectedStatus = 200,
    [string]$Upstream = "http://127.0.0.1:18080",
    [int]$ListenPort = 18082,
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Tool = Join-Path $ProjectRoot "app\tools\manage_defense.py"
$DefaultPython = Join-Path $ProjectRoot "app\.venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $DefaultPython) { $DefaultPython } else { "python" }
$PreviousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $ProjectRoot "app\tools"

try {
    $Arguments = @($Tool)
    if (-not [string]::IsNullOrWhiteSpace($Registry)) {
        $Arguments += @("--registry", $Registry)
    }
    $Arguments += $Action
    switch ($Action) {
        "smoke" {
            $Arguments += @(
                "--condition", $Condition,
                "--request-path", $RequestPath,
                "--expected-status", $ExpectedStatus.ToString()
            )
            if (-not [string]::IsNullOrWhiteSpace($Output)) {
                $Arguments += @("--output", $Output)
            }
        }
        "serve" {
            $Arguments += @(
                "--condition", $Condition,
                "--upstream", $Upstream,
                "--listen-port", $ListenPort.ToString()
            )
        }
    }
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "defense command failed with exit code $LASTEXITCODE"
    }
}
finally {
    if ($null -eq $PreviousPythonPath) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONPATH = $PreviousPythonPath
    }
}
