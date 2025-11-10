<#
.SYNOPSIS
    Will get a list of Resources, datasoures and instances to a csv

.DESCRIPTION
    Will get a list of Resources in a group (group is an input param)
    For each Resource, grab some Properties
    Will loop thru and get a list of DataSources. If they have Instances greater than 0 write T else F:
    Saving to a csv (filename is an input param)

    You should run against a group of devices similar eg Windows or Cisco Switches. This way you can see what is missing or differs from the norm.
    You can also identify 1 Resouce as your Gold standard and check others against that. So you can see what is missing. eg Memory.
	
	Datasources have the prefix set of DS_ to allow the CSV to be sorted. eg.DS_WinExchangeServices


.EXAMPLE
    Export-DeviceGroupAudit -GroupId 4791 -OutputPath "DBS_Audit.csv"

.NOTES
    Based on Audit_LMDatasoruces_for_a_group.ps1

.LINK
    https://github.com/AUrhino/LogicMonitor/blob/main/Export-DeviceGroupAudit.ps1

#>
function Export-DeviceGroupAudit {
    param (
        [int]$GroupId,
        [string]$OutputPath = "Audit_Group_for_DS_and_Instances.csv"
    )

    # Array of DataSources to exclude
    $excludedPatterns = @(
        "LogicMonitor_Collector",
        ".NetCLRLocksAndThreads",
        ".NetCLRExceptions",
        ".NetCLRMemory",
        ".NetCLRLoader",
        "HTTP_Page-",
        "HTTPS",
        "Port-",
        "Windows DNS Server-",
        "Win CUCM Process Stats-",
        "HTTP-",
        "Windows Stuck Print Jobs-",
        "dns",
        "WinCitrixServices-",
        "Win_WMI_UACTroubleshooter",
        "NTT_WMI_Status_Enhanced",
        "HostStatus",
        "Microsoft_Windows_Services",
        "Windows_Cluster_DiskPartitions",
        "Windows_Cluster_NodeState",
        "Windows_Cluster_ResourceState",
        "Application Pools-",
        "Windows_WMITimeOffset",
        "WinAutoServices-",
        "WinIIS-",
        "WinOS",
        "WinUDP",
        "MSMQ Service-",
        "MSMQ-",
        "Memcached-",
        "SSL_Certificates",
        "SSL_Certificate_Chains",
        "WinExchange"
    )

    function IsExcludedDatasource {
        param ($dsName)
        return $excludedPatterns | Where-Object { $dsName -like "*$_*" }
    }

    if (-not $PSBoundParameters.ContainsKey('GroupId')) {
        Write-Host "Example usage: Export-DeviceGroupAudit -GroupId 4791 -OutputPath 'C:\Reports\GroupAudit.csv'" -ForegroundColor Yellow
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $GroupId
    $outputData = @{}
    $totalDevices = $devices.Count
    $currentDevice = 0

    foreach ($item in $devices) {
        $currentDevice++
        $percentComplete = ($currentDevice / $totalDevices) * 100
        Write-Progress -Activity "Processing Devices" -Status "$currentDevice of $totalDevices complete" -PercentComplete $percentComplete

        $systemProperties = $item | Select-Object -ExpandProperty systemProperties
        $autoProperties   = $item | Select-Object -ExpandProperty autoProperties
        $customProperties = $item | Select-Object -ExpandProperty customProperties

        $deviceData = @{
            'sysoid'             = ($systemProperties | Where-Object { $_.Name -eq 'system.sysoid' }).Value
            'sysinfo'            = ($systemProperties | Where-Object { $_.Name -eq 'system.sysinfo' }).Value
            'hoststatus'         = ($systemProperties | Where-Object { $_.Name -eq 'system.hoststatus' }).Value
            'isCollector'        = ($systemProperties | Where-Object { $_.Name -eq 'system.collector' }).Value
            'model'              = ($autoProperties   | Where-Object { $_.Name -eq 'auto.endpoint.model' }).Value
            'wmi.operational'    = ($autoProperties   | Where-Object { $_.Name -eq 'auto.wmi.operational' }).Value
            'snmp.operational'   = ($autoProperties   | Where-Object { $_.Name -eq 'auto.snmp.operational.ntt' }).Value
            'PredefResourceType' = ($autoProperties   | Where-Object { $_.Name -eq 'predef.externalResourceType' }).Value
            'system.categories'  = ($customProperties | Where-Object { $_.Name -eq 'system.categories' }).Value
        }

        $datasources = Get-LMDeviceDatasourceList -id $item.id |
            Select-Object dataSourceName, instanceNumber |
            Where-Object { -not (IsExcludedDatasource $_.dataSourceName) } |
            Sort-Object dataSourceName

        $dsData = @{}
        foreach ($ds in $datasources) {
            $dsName = "DS_" + $ds.dataSourceName
            $dsData[$dsName] = if ($ds.instanceNumber -gt 0) { 'TRUE' } else { 'FALSE' }
        }

        $outputData[$item.displayName] = @{
            Properties = $deviceData
            Datasources = $dsData
        }
    }

    $csvData = @()
    foreach ($deviceName in $outputData.Keys) {
        $row = [PSCustomObject]@{ DisplayName = $deviceName }

        foreach ($propertyName in $outputData[$deviceName].Properties.Keys) {
            $row | Add-Member -MemberType NoteProperty -Name $propertyName -Value $outputData[$deviceName].Properties[$propertyName]
        }

        foreach ($dsName in $outputData[$deviceName].Datasources.Keys) {
            $row | Add-Member -MemberType NoteProperty -Name $dsName -Value $outputData[$deviceName].Datasources[$dsName]
        }

        $csvData += $row
    }

    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
}
