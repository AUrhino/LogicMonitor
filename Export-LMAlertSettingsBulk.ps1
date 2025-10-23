function Export-LMAlertSettingsBulk {
<#
.SYNOPSIS
    Exports LogicMonitor alert settings for multiple datasources in bulk.

.DESCRIPTION
    Loops through a list of datasources and exports alert settings for each to a separate CSV file.
    Supports filtering by datapoints or exporting all datapoints.
    Allows selecting specific columns using ExportItem.

.PARAMETER FolderName
    The LogicMonitor folder (device group).

.PARAMETER DatasourceNames
    Array of datasource names (e.g., HostStatus, BGP-, Cisco_CPU_SNMP).

.PARAMETER DataPointNames
    Array of datapoint names to filter or "ALL" for all datapoints.

.PARAMETER OutputDirectory
    Directory where CSV files will be saved. Default: Current directory.

.PARAMETER ExportItem
    Columns to include in the export. If not specified, all properties are exported.

.EXAMPLE
    Export-LMAlertSettingsBulk -FolderName "ESV" `
        -DatasourceNames @("HostStatus","BGP-","Cisco_CPU_SNMP") `
        -DataPointNames @("ALL") `
        -OutputDirectory "C:\Reports" `
        -ExportItem @("disableAlerting","alertExpr","dataPointName","globalAlertExpr",
                      "collectionInterval","alertTransitionInterval","alertClearTransitionInterval",
                      "alertForNoData","globalAlertForNoData","dataPointDescription")

.NOTES
    

.LINK
    https://github.com/AUrhino/LogicMonitor/blob/main/Export-LMAlertSettingsBulk.ps1

#>
    [CmdletBinding()]
    param (
        [string]$FolderName,
        [string[]]$DatasourceNames,
        [string[]]$DataPointNames,
        [string]$OutputDirectory = ".",
        [string[]]$ExportItem = @()
    )

    if (-not $FolderName -or -not $DatasourceNames -or -not $DataPointNames) {
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host 'Export-LMAlertSettingsBulk -FolderName "ESV" -DatasourceNames @("HostStatus","BGP-","Cisco_CPU_SNMP") -DataPointNames @("ALL") -OutputDirectory "C:\Reports"' -ForegroundColor Yellow
        Write-Host 'Get-Help Export-LMAlertSettingsBulk -Examples' -ForegroundColor Yellow
        return
    }

    foreach ($DatasourceName in $DatasourceNames) {
        try {
            Write-Host "Processing datasource: $DatasourceName" -ForegroundColor Cyan
            $DS = Get-LMDeviceGroupDatasourceAlertSetting -Name $FolderName -DatasourceName $DatasourceName
            if (-not $DS) {
                Write-Host "No alert settings found for '$DatasourceName'." -ForegroundColor Red
                continue
            }

            # Filter datapoints unless ALL is specified
            if ($DataPointNames -contains "ALL") {
                $FilteredDS = $DS
            } else {
                $FilteredDS = $DS | Where-Object { $_.dataPointName -and ($_.dataPointName -in $DataPointNames) }
            }

            if (-not $FilteredDS -or $FilteredDS.Count -eq 0) {
                Write-Host "No matching datapoints found for '$DatasourceName'." -ForegroundColor Yellow
                continue
            }

            # Validate ExportItem columns
            $OutputPath = Join-Path $OutputDirectory "$DatasourceName.csv"
            if ($ExportItem.Count -gt 0) {
                $validProps = ($FilteredDS | Get-Member -MemberType NoteProperty).Name
                $invalidProps = $ExportItem | Where-Object { $_ -notin $validProps }
                if ($invalidProps.Count -gt 0) {
                    Write-Host "Warning: Invalid columns for '$DatasourceName': $($invalidProps -join ', ')" -ForegroundColor Yellow
                    Write-Host "Valid columns: $($validProps -join ', ')" -ForegroundColor Cyan
                }
                $FilteredDS | Select-Object -Property $ExportItem | Export-Csv -Path $OutputPath -NoTypeInformation
            } else {
                $FilteredDS | Export-Csv -Path $OutputPath -NoTypeInformation
            }

            Write-Host "Exported alert settings for '$DatasourceName' to $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error processing '$DatasourceName': $_" -ForegroundColor Red
        }
    }
}
