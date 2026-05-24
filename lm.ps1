<#
.SYNOPSIS
    Custom connector for LogicMonitor

.DESCRIPTION
    Custom connector for LogicMonitor using PowerShell.

.EXAMPLE
    .\LM_CustomConnector.ps1

.NOTES
    Version 1.0

.NOTES
    Requires PowerShell 7.
    Required modules will be installed if missing.

.LINK
    
#>

#Requires -Version 7.0

$PSDefaultParameterValues['Out-File:Width'] = 2000
$FormatEnumerationLimit = -1

$RequiredModules = @(
    'Logic.Monitor',
    'PwshSpectreConsole'
)

foreach ($ModuleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        try {
            Write-Host "$ModuleName module not found. Attempting to install..."
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
        }
        catch {
            Write-Error "Failed to install $ModuleName module. Please install it manually.`nInstallation method:`nInstall-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber`n$_"
            exit 1
        }
    }

    try {
        Import-Module -Name $ModuleName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import $ModuleName module.`n$_"
        exit 1
    }
}

$Portals = @{
    Portal1 = @{
        AccountName = 'Portal1'
        AccessId    = 'XXXX'
        AccessKey   = 'YYY'
    }

    Portal2 = @{
        AccountName = 'Portal2'
        AccessId    = 'XXXX'
        AccessKey   = 'YYY'
    }

    Sandbox = @{
        AccountName = 'Sandbox'
        AccessId    = 'XXXX'
        AccessKey   = 'YYY'
    }
}

":thinking_face: What Portal are we working on?" | Format-SpectrePanel -Expand

$Choice = Read-SpectreSelection -Choices $Portals.Keys -PageSize 10 -EnableSearch

if (-not $Portals.ContainsKey($Choice)) {
    ":pouting_face: Unknown selection" | Format-SpectrePanel -Expand
    exit 1
}

$AccountName = $Portals[$Choice].AccountName
$AccessId    = $Portals[$Choice].AccessId
$AccessKey   = $Portals[$Choice].AccessKey

if (
    [string]::IsNullOrWhiteSpace($AccountName) -or
    [string]::IsNullOrWhiteSpace($AccessId) -or
    [string]::IsNullOrWhiteSpace($AccessKey) -or
    $AccessId -eq 'XXXX' -or
    $AccessKey -eq 'YYY'
) {
    ":pouting_face: Missing or placeholder credentials for $Choice" | Format-SpectrePanel -Expand
    exit 1
}

":face_with_tongue: Selected portal is: $AccountName" | Format-SpectrePanel

try {
    Connect-LMAccount `
        -AccessId $AccessId `
        -AccessKey $AccessKey `
        -AccountName $AccountName `
        -SkipVersionCheck

    ":partying_face: Connected to LogicMonitor portal: $AccountName" | Format-SpectrePanel
}
catch {
    Write-Error "Failed to connect to LogicMonitor portal '$AccountName'.`n$_"
    exit 1
}
