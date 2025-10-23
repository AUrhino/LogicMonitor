<#
.SYNOPSIS
    This file a collection of LogicMonitor functions

.DESCRIPTION
    This file a collection of LogicMonitor functions that will speed up processes used regularly
    Add an import to your LM connection script.
    . "C:\Users\rgillan\OneDrive - NTT\Documents\LogicMonitor\lm-functions.ps1"
     You can also ass this to your PROFILE.  ie  code $PROFILE


.EXAMPLE
    PS> .\lm-functions.ps1

.NOTES
    Version 1.7

.LINK
    https://github.com/ryan-gillan_nttltd/LM-snippets/blob/main/lm-functions.ps1
#>


#Ideas:
# Get a list of Companys under NTT-AU (return the ntt.company)
# Get an IPAM. eg IP list and instance list
#  get-lmdevice -displayname ss-core | select name,system.ips
#  get-lmdevice -displayname ss-core | select -expand systemProperties | where { $_.Name -eq "system.ips" }
#  get-lmdevice -displayname ss-core | select -expand autoProperties | where { $_.Name -eq "auto.network.address" }
#  get  list from ccdp and lldp


#chatGPT
#In Powershell
#Using Powershell module "Logic.Monitor"
#Assume already connected via api.


#------------------------
# Handy alias I use all the time. Can also be set: notepad $PROFILE
# Create alias SA for Select-Object
Set-Alias -Name SC 'Select-Object -expand customProperties'
Set-Alias -Name SA 'Select-Object -expand autoProperties'
Set-Alias -Name SIn 'Select-Object -expand inheritedProperties'

#------------------------


function Get-CurrentDate {
<#
.SYNOPSIS : This function will show the date in format dd-mm-yyyy
#>
    return (Get-Date).ToString("dd-MM-yyyy")
}
$currentDate = Get-CurrentDate
Write-Host "Today's date is: $currentDate"
#RUN: Get-CurrentDate
#------------------------
function Show-Dead {
    [String]$Company = $args[0]
    # checks for variable else shows example.
    if (-not $Company['']) {
        Write-Host "Example usage: Show-Dead CHED" -ForegroundColor Yellow
        return
    }
    Write-Host "Checking for dead devices on: ntt.company = $Company"
    $TotalCI = Get-LMDevice -Filter "customProperties -eq $($('{"name":"ntt.company","value":"' + $Company + '"}' | ConvertTo-Json)) "
    $Dead    = Get-LMDevice -Filter "customProperties -eq $($('{"name":"ntt.company","value":"' + $Company + '"}' | ConvertTo-Json)) -and systemProperties -eq $($('{"name":"system.hoststatus","value":"dead"}' | ConvertTo-Json))"
	Write-Host "Total: $($TotalCI.count) Dead: $($Dead.count)" -ForegroundColor Red
	$Dead
}
#RUN: Show-Dead CHED or Show-Dead APA |select name,displayName,preferredCollectorGroupName,description,disableAlerting,link,hostStatus | Export-Csv temp.csv
#------------------------

function Show-Devices {
    [String]$Company = $args[0]
    # checks for variable else shows example.
    if (-not $Company['']) {
        Write-Host "Example usage: Show-Devices CHED" -ForegroundColor Yellow
        return
    }
    Write-Host "Show devices on: ntt.company = $Company"
    Get-LMDevice -Filter "customProperties -eq $($('{"name":"ntt.company","value":"' + $Company + '"}' | ConvertTo-Json)) "
}
#RUN: Show-Devices CHED
#------------------------#------------------------

function Show-Devices_in_group {
    [String]$group = $args[0]
    # checks for variable else shows example.
    if (-not $group['']) {
        Write-Host "Example usage: Show-Devices_in_group 'ID'" -ForegroundColor Yellow
        return
    }
    # Retrieve devices from the specified device group
    $devices = Get-LMDeviceGroupDevices -Id $group -IncludeSubGroups $True
    $devices
}
#RUN: Show-Devices_in_group 'ID'


#------------------------
# show devices on a Collector.
function Show-DeviceOnCollector {
    param (
    [int]$collector
    )

    if (-not $collector) {
        Write-Host "Usage: Show-DeviceOnCollector -collector <collectorId>" -ForegroundColor Yellow
        return
    }

        Get-LMDevice -Filter "currentCollectorId -eq $collector" | Select-Object displayname, name, hostStatus | sort-Object displayname, hostStatus | Format-SpectreTable -title "Devices on Collector: $collector"
}
#RUN: Show-DeviceOnCollector -collector '<collectorId>'
#------------------------

function Show-DeadCollectors {
    $LM_Collectors = Get-LMCollector | Select-Object id,hostname,collectorGroupName,isDown | Where-Object { $_.isDown -eq $true }
    if ($LM_Collectors) {
        $LM_Collectors | ForEach-Object { Write-Host "Down Collectors: `n ID: $($_.id), Name: $($_.hostname), Group: $($_.collectorGroupName)" -ForegroundColor Red }
    } else {
        Write-Host "All Collectors are up." -ForegroundColor Green
    }
}
#RUN: Show-DeadCollectors
#------------------------

function Show-Collectors {
    $LM_Collectors = Get-LMCollector |select id,hostname,description,collectorGroupName | sort collectorGroupName | Format-SpectreTable
}
#RUN: Show-Collectors
#------------------------
function Show-folders {
    Get-LMDeviceGroup -id $(Get-LMDeviceGroup -Filter "fullPath -eq '/'").id | select -expand subGroups | Where-Object { $_.fullPath -like '*NTT*' } | select id,name,fullPath,numofHosts
}
#RUN: Show-folders
#------------------------
#function Show-Country-folders {
#    [String]$fullPath = $args[0]
#    # checks for variable else shows example.
#    if (-not $fullPath['']) {
#        Write-Host "Example usage: Show-Country-folders NTT-AU" -ForegroundColor Yellow
#        return
#    }
#    Get-LMDeviceGroup -id $(Get-LMDeviceGroup -Filter "fullPath -eq '$fullPath'").id | select -expand subGroups | select id, name, fullPath,numofHosts
#}
##RUN: Show-Country-folders NTT-AU
#
#------------------------
function Show-Country-folders  {
    param (
        [string]$fullPath
    )

    if (-not $fullPath) {
        Write-Host "Example: Show-Country-folders -fullPath 'NTT-AU'" -ForegroundColor Yellow
        return
    }

    $group = Get-LMDeviceGroup -Filter "fullPath -eq '$fullPath'"
    $subGroups = $group.subGroups | Sort-Object Name

    $result = @()

    foreach ($subGroup in $subGroups) {
        $result += [PSCustomObject]@{
            ID            = $subGroup.ID
            Name          = $subGroup.Name
            FullPath      = $subGroup.FullPath
            NumberOfHosts = $subGroup.numOfHosts
            #groupStatus   = $subGroup.groupStatus
        }
    }

    return $result
}
#RUN: Show-Country-folders -fullPath 'NTT-AU'
#------------------------
function Show-Country-folders_plus_DEAD {
    param (
        [string]$fullPath
    )

    if (-not $fullPath) {
        Write-Host "Example: Show-Country-folders -fullPath 'NTT-AU'" -ForegroundColor Yellow
        return
    }

    $group = Get-LMDeviceGroup -Filter "fullPath -eq '$fullPath'"
    $subGroups = $group.subGroups | Sort-Object Name

    $result = @()

    foreach ($subGroup in $subGroups) {
        $FullPath = $subGroup.FullPath
        $NumberOfHosts = $subGroup.numOfHosts

        $filter = 'systemProperties -eq "{\"name\":\"system.staticgroups\",\"value\":\"' + $FullPath + '/All\"}" -and hostStatus -eq "dead"'
        $DEADCount = Get-LMDevice -Filter $filter | Measure-Object | Select-Object -ExpandProperty Count

        $DEADPercentage = if ($NumberOfHosts -gt 0) {
            [math]::Round(($DEADCount / $NumberOfHosts) * 100, 0)
        } else {
            0
        }

        $result += [PSCustomObject]@{
            FullPath        = $FullPath
            NumberOfHosts   = $NumberOfHosts
            DEADCount       = $DEADCount
            DEADPercentage  = "$DEADPercentage %"
        }
    }

    return $result
}

# Example usage:
#Show-Country-folders_plus_DEAD -fullPath 'NTT-AU'

# Example usage:
#RUN: Show-Country-folders_plus_DEAD -fullPath 'NTT-AU'

#---------------------------------

function Show-GroupTree {
    param (
        [int]$parentId = $args[0],
        [int]$level = 10
    )
    $groups = Get-LMDeviceGroup

    $groupLookup = @{}
    foreach ($group in $groups) {
        if (-not $groupLookup.ContainsKey($group.ParentId)) {
            $groupLookup[$group.ParentId] = @()
        }
        $groupLookup[$group.ParentId] += $group
    }

    if ($groupLookup.ContainsKey($parentId)) {
        foreach ($group in $groupLookup[$parentId] | Sort-Object Name) {
            $indent = ("|  " * $level) + "|--"
            Write-Output ($indent + " " + $group.Name)
            Show-GroupTree -parentId $group.Id -level ($level + 1)
        }
    }
}

#RUN: Show-GroupTree 4615

#---------------------------------
function Show-Country-folders_plus_DEAD {
    param (
        [string]$fullPath
    )

    if (-not $fullPath) {
        Write-Host "Example: Show-Country-folders -fullPath 'NTT-AU'" -ForegroundColor Yellow
        return
    }

    $group = Get-LMDeviceGroup -Filter "fullPath -eq '$fullPath'"
    $subGroups = $group.subGroups | Sort-Object Name

    $result = @()

    foreach ($subGroup in $subGroups) {
        $FullPath = $subGroup.FullPath
        $NumberOfHosts = $subGroup.numOfHosts

        $filter = 'systemProperties -eq "{\"name\":\"system.staticgroups\",\"value\":\"' + $FullPath + '/All\"}" -and hostStatus -eq "dead"'
        $DEADCount = Get-LMDevice -Filter $filter | Measure-Object | Select-Object -ExpandProperty Count

        $DEADPercentage = if ($NumberOfHosts -gt 0) {
            [math]::Round(($DEADCount / $NumberOfHosts) * 100, 0)
        } else {
            0
        }

        $result += [PSCustomObject]@{
            FullPath        = $FullPath
            NumberOfHosts   = $NumberOfHosts
            DEADCount       = $DEADCount
            DEADPercentage  = "$DEADPercentage %"
        }
    }

    $result | Format-SpectreTable
}

# Example usage:
#Show-Country-folders_plus_DEAD -fullPath 'NTT-AU'


#RUN: Get-GroupDetails -Parentid 4615


#------------------------
function Show-Country-folders_plus_DEAD_v2 {
    param (
        [string]$fullPath,
        [string]$EmailTo,
        [string]$EmailSubject = "Country Folder DEAD Report",
        [string]$EmailBody = "Please find attached the DEAD report for the specified country folder.",
        [string]$ExportPath = "$env:TEMP\CountryFolder_DEAD_Report.csv"
    )

    if (-not $fullPath) {
        Write-Host "Example: Show-Country-folders_plus_DEAD_v2 -fullPath 'NTT-AU' -EmailTo 'ryan.gillan@nttdata.com'" -ForegroundColor Yellow
        return
    }

    $group = Get-LMDeviceGroup -Filter "fullPath -eq '$fullPath'"
    $subGroups = $group.subGroups | Sort-Object Name

    $result = @()

    foreach ($subGroup in $subGroups) {
        $FullPath = $subGroup.FullPath
        $NumberOfHosts = $subGroup.numOfHosts

        $filter = 'systemProperties -eq "{\"name\":\"system.staticgroups\",\"value\":\"' + $FullPath + '/All\"}" -and hostStatus -eq "dead"'
        $DEADCount = Get-LMDevice -Filter $filter | Measure-Object | Select-Object -ExpandProperty Count

        $DEADPercentage = if ($NumberOfHosts -gt 0) {
            [math]::Round(($DEADCount / $NumberOfHosts) * 100, 0)
        } else {
            0
        }

        $result += [PSCustomObject]@{
            FullPath        = $FullPath
            NumberOfHosts   = $NumberOfHosts
            DEADCount       = $DEADCount
            DEADPercentage  = "$DEADPercentage %"
        }
    }

    $result | Format-SpectreTable

    # Export to CSV
    $result | Export-Csv -Path $ExportPath -NoTypeInformation

    # Send email if EmailTo is provided
    if ($EmailTo) {
        Send-Email -To $EmailTo -Subject $EmailSubject -Body $EmailBody -Attachment $ExportPath
    }
}

#RUN: Show-Country-folders_plus_DEAD_v2 -fullPath 'NTT-AU' -EmailTo 'ryan.gillan@nttdata.com'


#------------------------
function Get-GroupDetails_to_csv {
    param (
        [int]$Parentid
    )

    # Get the full path of the parent group
    $ParentGroup = Get-LMDeviceGroup -id $Parentid
    $ParentFullPath = $ParentGroup.fullPath

    # Function to display group details with indentation
    function Display-GroupDetails {
        param (
            [string]$Indent,
            [object]$Group
        )
        $GroupDetails = Get-LMDeviceGroup -id $Group.id | select name, fullPath, subGroups
        $GroupDetails | ForEach-Object {
            [PSCustomObject]@{
                FullPath = $_.fullPath
            }
            if ($_.subGroups) {
                foreach ($subGroup in $_.subGroups) {
                    Display-GroupDetails -Indent "$Indent    " -Group $subGroup
                }
            }
        }
    }

    # Collect all group details in a list
    $GroupList = @()

    # Display the parent group details
    $GroupList += [PSCustomObject]@{
        FullPath = $ParentFullPath
    }

    # Get all subgroups of the parent group
    $SubGroups = Get-LMDeviceGroup -id $Parentid | select -expandProperty subGroups

    # Iterate through each subgroup and collect relevant information with indentation
    foreach ($group in $SubGroups) {
        $GroupList += Display-GroupDetails -Indent "    " -Group $group
    }

    # Save the group details to a CSV file
    $GroupList | Select-Object -Property FullPath | Export-Csv -Path "output.csv" -NoTypeInformation
    Write-Host "File exported to output.csv in current path."
}

#RUN: Get-GroupDetails_to_csv -Parentid 4615 #wow australia

#------------------------
function Get-GroupDetails_with_devicecount {
    param (
        [int]$Parentid
    )

    # Get the full path of the parent group
    $ParentGroup = Get-LMDeviceGroup -id $Parentid
    $ParentFullPath = $ParentGroup.fullPath

    # Function to display group details with indentation
    function Display-GroupDetails {
        param (
            [string]$Indent,
            [object]$Group
        )
        $GroupDetails = Get-LMDeviceGroup -id $Group.id | select id, name, fullPath, subGroups
        $GroupDetails | ForEach-Object {
            if ($_.fullPath -match '\d') {
                [PSCustomObject]@{
                    FullPath    = $_.fullPath
                    DeviceCount = (Get-LMDeviceGroupDevices -Id $_.id).count
                }
            }
            if ($_.subGroups) {
                foreach ($subGroup in $_.subGroups) {
                    Display-GroupDetails -Indent "$Indent    " -Group $subGroup
                }
            }
        }
    }

    # Collect all group details in a list
    $GroupList = @()

    # Display the parent group details if it contains a number
    if ($ParentFullPath -match '\d') {
        $GroupList += [PSCustomObject]@{
            FullPath    = $ParentFullPath
            DeviceCount = (Get-LMDeviceGroupDevices -Id $ParentGroup.id).count
        }
    }

    # Get all subgroups of the parent group
    $SubGroups = Get-LMDeviceGroup -id $Parentid | select -expandProperty subGroups

    # Iterate through each subgroup and collect relevant information with indentation
    foreach ($group in $SubGroups) {
        $GroupList += Display-GroupDetails -Indent "    " -Group $group
    }

    # Save the group details to a CSV file
    $GroupList | Select-Object -Property FullPath, DeviceCount | Export-Csv -Path "Australia_folders_with_devicecount.csv" -NoTypeInformation
}

#RUN: Get-GroupDetails_with_devicecount -Parentid 11232

#------------------------

function Show-random {
    # List of names
    $names = @("Ryan", "Mike", "David", "Justin")
    # Pick a random name
    $randomName = Get-Random -InputObject $names
    # Print the result
    Write-Host "The randomly selected person is: $randomName"
}
#RUN: 
#------------------------
function Show-DataSources {
    [String]$CI = $args[0]
    # checks for variable else shows example.
    if (-not $CI['']) {
        Write-Host "Example usage: Show-DataSources ss-core" -ForegroundColor Yellow
        return
    }
    $device = Get-LMDevice -DisplayName $CI
    # Check if the device object is not null
    if ($device) {
        # Get the data source list for the device and filter where instanceNumber is not 0
        $dataSources = Get-LMDeviceDatasourceList -Id $device.id | Where-Object { $_.instanceNumber -ne 0 } | select dataSourceName, instanceNumber | sort dataSourceName
        # Print the data sources
        $dataSources | ForEach-Object { Write-Output "DataSource: $($_.dataSourceName), InstanceCount: $($_.instanceNumber)" }
    } else {
        Write-Output "Device $CI not found."
    }
}
# Add an alias for the function
Set-Alias -Name sds -Value Show-DataSources
#RUN: 
#------------------------
function Show-DataSources-full {
    [String]$CI = $args[0]
    # checks for variable else shows example.
    if (-not $CI['']) {
        Write-Host "Example usage: Show-DataSources-full ss-core" -ForegroundColor Yellow
        return
    }
    $device = Get-LMDevice -DisplayName $CI
    # Check if the device object is not null
    if ($device) {
        # Get the data source list for the device
        $dataSources = Get-LMDeviceDatasourceList -Id $device.id | select dataSourceName, instanceNumber | sort dataSourceName
        # Print the data sources
        $dataSources | ForEach-Object { Write-Output "DataSource: $($_.dataSourceName), InstanceCount: $($_.instanceNumber)" }
    } else {
        Write-Output "Device $CI not found."
    }
}
# Add an alias for the function
Set-Alias -Name sdsf -Value Show-DataSources-full
#RUN: 
#------------------------

function Show-Data {
    [String]$CI = $args[0] #CI to query
    [String]$ds = $args[1] #Datasource to query
    # checks for variable else shows example.
    if (-not $CI['']) {
        Write-Host "Example usage: Show-Data ss-core NTT_SNMP_Status" -ForegroundColor Yellow
        return
    }
    
    $device = Get-LMDevice -DisplayName $CI
    # Check if the device object is not null
    if ($device) {
        $ds = Get-LMDeviceInstanceList -Filter ("name -contains 'NTT_SNMP_Status'") -Name $(Get-LMDevice -displayname AU-ADL-TIP-RT-01).name | select name,deviceDisplayName,id
        # Print the data sources
        Get-LMDeviceInstanceData -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date) -Ids $ds.id -AggregationType "last" -Period 1 | select dataSourceName, dataPoints, values
    } else {
        Write-Output "Device $CI not found. `nTo use this function PS > Show-Data devicename"
    }
}
# Add an alias for the function
Set-Alias -Name sd -Value Show-Data
#RUN: Show-Data ss-core NTT_SNMP_Status
#------------------------
#get-lmdevice -displayname rprdms406 | select displayname,name,hostStatus,sdtStatus
#-Filter "sdtStatus -contains 'SDT'"
function Show-SDT {
    [String]$Company = $args[0]
    # checks for variable else shows example.
    if (-not $Company['']) {
        Write-Host "Example usage: Show-SDT CHED" -ForegroundColor Yellow
        return
    }
    Write-Host "Checking for devices on: ntt.company = $Company"
    Get-LMDevice -Filter "customProperties -eq $($('{"name":"ntt.company","value":"' + $Company + '"}' | ConvertTo-Json))" | select displayname,name,hoststatus,sdtStatus | sort displayname
}
# Add an alias for the function
Set-Alias -Name ssdt -Value Show-SDT
#RUN: Show-SDT CHED
#------------------------
#$ds = Get-LMDeviceInstanceList -Filter ("name -eq 'NTT_SNMP_Status'") -Name $(Get-LMDevice -displayname AU-ADL-TIP-RT-01).name | select name,deviceDisplayName,id
#Get-LMDeviceInstanceData -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date) -Ids $ds.id -AggregationType "last" -Period 1 | select dataSourceName, dataPoints, values

#------------------------
function Show-Netflow {
    [String]$Company = $args[0]
    # checks for variable else shows example.
    if (-not $Company['']) {
        Write-Host "Example usage: Show-Netflow 33" -ForegroundColor Yellow
        return
    }
    Write-Host "Show Netflow enabled devices on: ntt.company = $Company"
    Get-LMDevice -Filter "customProperties -eq $($('{"name":"ntt.company","value":"' + $Company + '"}' | ConvertTo-Json)) -and systemProperties -eq $('{"name":"system.enablenetflow","value":"true"}' | ConvertTo-Json) "
}
Set-Alias -Name snf -Value Show-Netflow

#RUN: Show-Netflow 33
#------------------------
function Show-Dead_On_Collector {
    [String]$Collector = $args[0]
    # checks for variable else shows example.
    if (-not $Collector['']) {
        Write-Host "Example usage: Show-Dead_On_Collector 333" -ForegroundColor Yellow
        return
    }
    # Get the number of hosts for the specified collector
    $hosts = Get-LMCollector -id $Collector | Select-Object numberOfHosts
    # Get the dead devices for the specified collector
    $dead = Get-LMDevice -Filter "currentCollectorId -eq $Collector" | 
            Select-Object displayname, hostStatus | 
            Sort-Object hostStatus | 
            Where-Object { $_.hostStatus -eq "dead" }

    # Display the information
    Write-Host "Collector: `n ID: $($Collector), Hosts: $($hosts), Dead: $($dead)" -ForegroundColor Red
}
Set-Alias -Name sdh -Value Show-Dead_On_Collector
#RUN: Show-Dead_On_Collector 33

#------------------------
function Show-DisabledAlertsOnCollector {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CollectorId
    )

    try {
        # Get collector details
        $collector = Get-LMCollector -Id $CollectorId
        if (-not $collector) {
            Write-Host "Collector with ID '$CollectorId' not found." -ForegroundColor Red
            return
        }

        $hostCount = $collector.numberOfHosts

        # Get devices with alerting disabled
        $disabledAlerts = Get-LMDevice -Filter "currentCollectorId -eq $CollectorId -and disableAlerting -eq 'True'" |
            Select-Object displayName, hostStatus, disableAlerting |
            Where-Object { $_.disableAlerting -eq "True" }

        # Output results
        Write-Host "`nCollector ID: $CollectorId" -ForegroundColor Cyan
        Write-Host "Number of Hosts: $hostCount" -ForegroundColor Cyan
        Write-Host "Devices with Alerting Disabled:" -ForegroundColor Yellow

        if ($disabledAlerts.Count -eq 0) {
            Write-Host "No devices with alerting disabled found on this collector." -ForegroundColor Green
        } else {
            $disabledAlerts | Format-Table displayName, hostStatus, disableAlerting
        }
    }
    catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}


#RUN: Show-Disabled_Alerts_On_Resources_on_Collector 33


#------------------------
function Show-MissingSSID {
    param (
        [string]$id = ''
    )
    $Updated = 0
    $NotUpdated = 0
    $NoSysIdDevices = @()

    # Get a list of devices in a group to set the links.
    $Devices = Get-LMDeviceGroupDevices -Id $id

    # Loop through devices in the listed group
    foreach ($Device in $Devices) {
        # Check if 'ntt.ci.sys_id' tag is present and its value is not null
        $currentPropValue = $Device.customproperties.value[$Device.customProperties.name.IndexOf('ntt.ci.sys_id')]
        $isEDCEventPropValue = $Device.inheritedProperties.value[$Device.inheritedProperties.name.IndexOf('isEDCEvent')]

        # Check if the custom property exists and the link is not already set
        if ($currentPropValue -and $Device.customProperties.name.IndexOf('ntt.ci.sys_id') -ne -1) {
            $currentLink = (Get-LMDevice -displayname $Device.displayName).Link
            if (-not $currentLink) {
                $Updated++
                Write-Host "Missing on device: "$Device.displayname "with the sys_id of: " $currentPropValue
            } else {
                Write-Host "Skipping device: "$Device.displayname "as it already has a link set."
            }
        } else {
            $NotUpdated++
            Write-Host "ERROR: The property of ntt.ci.sys_id is NOT SET on:" $Device.displayname -ForegroundColor RED
            $NoSysIdDevices += $Device.displayname
        }
    }
    # Show
    $NoSysIdDevices
}

#RUN: Show-MissingSSID -id 'YourGroupID'
#RUN: Show-MissingSSID -id 'YourGroupID'| Out-File -FilePath "NoSysIdDevices.txt"

#------------------------
function Show-MissingCompany {
    param (
        [string]$id = ''
    )
    $Updated = 0
    $NotUpdated = 0
    $NoSysIdDevices = @()

    # Get a list of devices in a group to set the links.
    $Devices = Get-LMDeviceGroupDevices -Id $id

    # Loop through devices in the listed group
    foreach ($Device in $Devices) {
        # Check if 'ntt.company' tag is present and its value is not null
        $currentPropValue = $Device.customproperties.value[$Device.customProperties.name.IndexOf('ntt.company')]
        $isEDCEventPropValue = $Device.inheritedProperties.value[$Device.inheritedProperties.name.IndexOf('isEDCEvent')]

        # Check if the custom property exists and the link is not already set
        if ($currentPropValue -and $Device.customProperties.name.IndexOf('ntt.ci.sys_id') -ne -1) {
            $currentLink = (Get-LMDevice -displayname $Device.displayName).Link
            if (-not $currentLink) {
                $Updated++
                Write-Host "Missing on device: "$Device.displayname "with the sys_id of: " $currentPropValue
            } else {
                Write-Host "Skipping device: "$Device.displayname "as it already has a link set."
            }
        } else {
            $NotUpdated++
            Write-Host "ERROR: The property of ntt.ci.sys_id is NOT SET on:" $Device.displayname -ForegroundColor RED
            $NoIdDevices += $Device.displayname
        }
    }
    # Show
    $NoIdDevices
}

#RUN: Show-MissingCompany -id 'YourGroupID'
#RUN: Show-MissingCompany -id 'YourGroupID'| Out-File -FilePath "MissingCompany.txt"
#------------------------
function Get-SwaggerDetails {
    param (
        [string]$url = "https://www.logicmonitor.com/swagger-ui-master/api-v3/dist/swagger.json",
        [string]$methodFilter = "GET",
        [string]$base = "https://Company.logicmonitor.com/santaba/rest"
    )

    # Fetch the Swagger file from the URL
    Invoke-WebRequest -Uri $url -OutFile "example_swagger.json"

    # Read and convert the Swagger file
    $swagger = Get-Content -Path "example_swagger.json" -Encoding UTF8 -Raw | ConvertFrom-Json

    # Filter and print the paths and methods
    $swagger.paths.PSObject.Properties | ForEach-Object {
        $path = $_.Name
        $methods = $_.Value.PSObject.Properties.Name

        if ($methods -contains $methodFilter) {
            [pscustomobject]@{
                path = $path
                method = $methodFilter
                fullPath = "$base$path"
            }
        }
    }
}

#RUN: Get-SwaggerDetails

#------------------------
function Show_Stale_Devices {
    param (
    [int]$days
)

    # Calculate the stale date in Unix time
    $staleDate = [int][double]::Parse((Get-Date).AddDays(-$days).ToUniversalTime().Subtract((Get-Date "1/1/1970")).TotalSeconds)

    # Get the stale devices based on the calculated stale date
    $staleDevices = Get-LMDevice -Filter "lastDataTime -gt '$staleDate'"

    # Display the stale devices
    if ($staleDevices) {
            Write-Host "Stale devices found:"
            $staleDevices | ForEach-Object { Write-Host $_.Name, $_.Diplayname, $_.preferredCollectorGroupName }
    } else {
            Write-Host "No stale devices found."
    }
}
#RUN: Show_Stale_Devices -days 30

#------------------------
function Generate-RandomPassword {
    param (
        [int]$Length = 14
    )

    $chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*_()" #removed i,o,1 etc
    $password = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
    return $password
}
#RUN: Generate-RandomPassword
#------------------------
# Create a user
function Create_LMUser {
    param (
    [string]$Username,
    [string]$FirstName,
    [string]$LastName,
    [string]$Email,
    [string]$RoleName,
    [string]$Mobile,
    [string]$Ticket
)

    if (-not $PSBoundParameters['Username']) {
        Write-Host "Example usage: Create_LMUser -Username <username> -FirstName <firstname> -LastName <lastname> -Email <email> -RoleName <rolename> -Mobile <mobile> -Ticket <Ticket>"
    return
    }

    $Username = $Username.ToLower() # Change to lowercase
    $Email    = $Email.ToLower()    # Change to lowercase
    $Password = Generate-RandomPassword

    # Create new user with roles
    New-LMUser -Username $Username `
        -Password $Password `
        -FirstName $FirstName `
        -LastName $LastName `
        -Email $Email `
        -RoleNames @($RoleName) `
        -ForcePasswordChange $true `

    # Set user phone number
    Set-LMUser -Username $Username -Phone $Mobile -note $Ticket

    # Print summary table
    $table = @(
    [pscustomobject]@{Name="Username"; Value=$Username},
    [pscustomobject]@{Name="First Name"; Value=$FirstName},
    [pscustomobject]@{Name="Last Name"; Value=$LastName},
    [pscustomobject]@{Name="Email"; Value=$Email},
    [pscustomobject]@{Name="Role Name"; Value=$RoleName},
    [pscustomobject]@{Name="Mobile"; Value=$Mobile},
    [pscustomobject]@{Name="Ticket"; Value=$Ticket},
    [pscustomobject]@{Name="Password"; Value=$Password}
)

    Format-SpectreTable -Title "Creation summary" -Data $table
}

#RUN: Create_LMUser -Username michael.ceola@global.ntt -FirstName Michael -LastName Ceola -Email michael.ceola@global.ntt -RoleName administrator -Mobile 0411123123 -Ticket SVR12345

#------------------------

function Set-DeviceMonitoringState_device {
    param (
        [int]$displayname
    )
    if (-not $displayname['']) {
        Write-Host "Example usage: Set-DeviceMonitoringState_device 'displayname'" -ForegroundColor Yellow
        return
    }
    Get-LMDevice -displayname $displayname | Set-LMDevice -Properties @{'ntt.monitoring.status' = 'Active'}
    }

#RUN: Set-DeviceMonitoringState_device -displayname ss-core
#------------------------
function Set-DeviceMonitoringState_Group {
    param (
        [int]$GroupId
    )
    if (-not $GroupId['']) {
        Write-Host "Example usage: Set-DeviceMonitoringState_Group -GroupId 'id'" -ForegroundColor Yellow
        return
    }
    $devices = Get-LMDeviceGroupDevices -id $GroupId
    foreach ($device in $devices.id) {
        Set-LMDevice -Id $device -Properties @{'ntt.monitoring.status' = 'Active'}
    }
}
#RUN: Set-DeviceMonitoringState_Group -GroupId 6700

#------------------------
function Show_BackupConfig {
    param (
        [string]$displayname
    )
    if (-not $displayname['']) {
        Write-Host "Example usage: Show_BackupConfig -displayname 'displayname'" -ForegroundColor Yellow
        return
    }
    $devices = Get-LMDevice -displayname $displayname
    Export-LMDeviceConfigBackup -deviceid $Ci.id
}

#RUN: Show_BackupConfig -GroupId 6700



#------------------------
function Show-Roles {
    $roles = Get-LMRole | Select-Object id, name, description
    $table = @()

    foreach ($role in $roles) {
        $table += [pscustomobject]@{
            ID          = $role.id
            Name        = $role.name
            Description = $role.description
        }
    }

    Format-SpectreTable -Title "Creation Summary" -Data $table
}

#RUN: Show-Roles
#------------------------
# Get a list of users and show the key fields.
function Show-Users {
    $users = Get-LMUser | Select-Object id, username, email, status, note, roles
    $table = @()

    foreach ($user in $users) {
            $roleNames = $user.roles | ForEach-Object { $_.name }
            $table += [pscustomobject]@{
                    ID                = $user.id
                    Username    = $user.username
                    email          = $user.email
                    status        = $user.status
                    note            = $user.note
                    roles          = -join $roleNames -join ", "
            }
    }

    Format-SpectreTable -Title "Creation Summary" -Data $table
}
#RUN: Show-Users

#------------------------
# Get a list of devices in a Services Aggregator
function Show_LMServices {
    $LMServices = Get-LMDevice -Filter 'collectorDescription -eq "Service Data Aggregator"'
    $results = @()
    foreach ($item in $LMServices) {
        $systemProperties = $item | Select-Object -ExpandProperty SystemProperties
        $customProperties = $item | Select-Object -ExpandProperty CustomProperties
        $groups = ($systemProperties | Where-Object { $_.Name -eq 'system.groups' }).Value
        $banner = ($customProperties | Where-Object { $_.Name -eq 'ntt.wow.banner' }).Value
        $siteid = ($customProperties | Where-Object { $_.Name -eq 'ntt.site.id' }).Value
        $state = ($customProperties | Where-Object { $_.Name -eq 'location.state' }).Value
        if ($item.Name -like "*Availability*") {
            $results += [PSCustomObject]@{
                Id     = $item.Id
                Name   = $item.Name
                Group  = $groups
                Banner  = $banner
                SiteID = $siteid
                State  = $state
            }
        }
    }
    Format-SpectreTable -Title "LM Services Summary" -Data $results
}

#RUN: Show_LMServices
# To set a Service location
# Get-LMDevice -id 30841 |Set-LMDevice -Properties @{'ntt.location.state'="NSW"}

#------------------------
function Show_LMServices_2_csv {
    $LMServices = Get-LMDevice -Filter 'collectorDescription -eq "Service Data Aggregator"'
    $results = @()
    foreach ($item in $LMServices) {
        $systemProperties = $item              | Select-Object -ExpandProperty SystemProperties
        $customProperties = $item              | Select-Object -ExpandProperty CustomProperties
        $groups           = ($systemProperties | Where-Object { $_.Name -eq 'system.groups' }).Value
        $banner           = ($customProperties | Where-Object { $_.Name -eq 'ntt.wow.banner' }).Value
        $siteid           = ($customProperties | Where-Object { $_.Name -eq 'ntt.site.id' }).Value
        $state            = ($customProperties | Where-Object { $_.Name -eq 'location.state' }).Value
        $Locn             = ($customProperties | Where-Object { $_.Name -eq 'location' }).Value
        if ($item.Name -like "*Availability*") {
            $results += [PSCustomObject]@{
                Id         = $item.Id
                Name       = $item.Name
                Group      = $groups
                Banner     = $banner
                SiteID     = $siteid
                State      = $state
                Location   = $Locn
            }
        }
    }
    $results | Export-Csv -Path "LMServicesSummary.csv" -NoTypeInformation
    Write-Output "CSV file 'LMServicesSummary.csv' has been created."
}

#RUN: Show_LMServices_2_csv

#------------------------
# Get a list of Services groups
function Show_LMServicesGroups {
    $LMServices = Get-LMDeviceGroup  -Filter 'groupType -eq "BizService"'
    $results = @()
    foreach ($item in $LMServices) {
        $results += [PSCustomObject]@{
            Id     = $item.Id
            Name   = $item.Name
            fullPath  = $item.$fullPath
            appliesTo  = $item.$appliesTo
            }
        }
    Format-SpectreTable -Title "LM Services group Summary" -Data $results
}

#RUN: Show_LMServicesGroups 


#------------------------
function Find-Service {
    param (
        [string]$searchTerm
    )
    Get-LMDevice -Filter 'collectorDescription -eq "Service Data Aggregator"' | Where-Object { $_.name -like "*$searchTerm*" }
}

#RUN: Find-Service -searchTerm "yourSearchTerm


#------------------------
function Find-Report {
    [CmdletBinding()]
    param (
        [ValidateSet("Alert", "SLA", "trends", "threshold", "inventory", "metric", "CPU", "Interface", "Website", "Netflow")]
        [string]$Type,

        [ValidateSet("HTML", "PDF", "CSV")]
        [string]$output,

        [string]$HostsVal,
        [string]$LastModifyUserName,
        [string]$Name,
        [string]$Description
    )

    $reports = Get-LMReport | Select-Object id, name, description, type, schedule, lastmodifyUserName

    if (-not $PSBoundParameters.Keys.Count) {
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host "Find-Report -Type 'Alert' -Name 'CPU' -output 'CSV'" -ForegroundColor Yellow
        return $reports
    }

    if ($Type) {
        $reports = $reports | Where-Object { $_.type -eq $Type }
    }

    if ($LastModifyUserName) {
        $reports = $reports | Where-Object { $_.lastmodifyUserName -like "*$LastModifyUserName*" }
    }

    if ($Name) {
        $reports = $reports | Where-Object { $_.name -like "*$Name*" }
    }

    if ($Description) {
        $reports = $reports | Where-Object { $_.description -like "*$Description*" }
    }

    if ($HostsVal) {
        $reports = $reports | Where-Object { $_.description -like "*$HostsVal*" -or $_.name -like "*$HostsVal*" }
    }

    if ($output) {
        switch ($output) {
            "HTML" { $reports | ConvertTo-Html | Out-String }
            "PDF"  { Write-Warning "PDF export not supported directly in PowerShell. Consider exporting to CSV and converting externally." }
            "CSV"  { $reports | Export-Csv -Path "LMReports.csv" -NoTypeInformation; Write-Output "Exported to LMReports.csv" }
        }
    } else {
        return $reports
    }
}


#RUN: Find-Report -Type 'Alert' -Name 'CPU' -output 'CSV'
#     Find-Report -Type '"<Alert|SLA|trends|threshold|inventory|metric|CPU|Interface|Website|Netflow>"'
#     Find-Report --LastModifyUserName 'ryan'
#     Find-Report -Name 'CPU|whatever'
#     Find-Report -output 'CSV|HTML|PDF'

#------------------------
# Print-FolderTree_2_csv 
function Print-FolderTree_2_csv {
    param (
        [int]$ID,
        [string]$OutputFile
    )

    if (-not $ID) {
        Write-Host "Example usage: Print-FolderTree -ID 'ID' -OutputFile 'OutputFile.csv'" -ForegroundColor Yellow
        Write-Host "Sending the clipboard: Print-FolderTree -ID 'ID' -OutputFile 'OutputFile.csv' | clip" -ForegroundColor Yellow
        return
    }

    # Get the full path of the parent group
    $ParentGroup = Get-LMDeviceGroup -id $ID
    $ParentFullPath = $ParentGroup.fullPath

    # Function to display group details with indentation
    function Display-GroupDetails {
        param (
            [string]$Indent,
            [object]$Group
        )
        $GroupDetails = Get-LMDeviceGroup -id $Group.id | Select-Object name, fullPath, subGroups
        $GroupDetails | ForEach-Object {
            [PSCustomObject]@{
                Name     = "$Indent$($_.name)"
                FullPath = $_.fullPath
            }
            if ($_.subGroups) {
                foreach ($subGroup in $_.subGroups) {
                    Display-GroupDetails -Indent "$Indent    " -Group $subGroup
                }
            }
        }
    }

    # Collect all group details in a list
    $GroupList = @()

    # Display the parent group details
    $GroupList += [PSCustomObject]@{
        Name     = $ParentGroup.name
        FullPath = $ParentFullPath
    }

    # Get all subgroups of the parent group
    $SubGroups = Get-LMDeviceGroup -id $ID | Select-Object -expandProperty subGroups

    # Iterate through each subgroup and collect relevant information with indentation
    foreach ($group in $SubGroups) {
        $GroupList += Display-GroupDetails -Indent "    " -Group $group
    }

    # Output the group details to CSV
    if ($OutputFile) {
        $GroupList | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Folder tree exported to $OutputFile" -ForegroundColor Green
    } else {
        $GroupList | Format-Table
    }
}
#RUN: Print-FolderTree_2_csv -id 11234 -OutputFile 'Australia_Folders.csv'
#------------------------
function Print-FolderTree_2_csv_flatstructure {
    param (
        [int]$ID,
        [string]$OutputFile
    )

    if (-not $ID) {
        Write-Host "Example usage: Print-FolderTree_2_csv_flatstructure -ID 'ID' -OutputFile 'OutputFile.csv'" -ForegroundColor Yellow
        Write-Host "Sending the clipboard: Print-FolderTree_2_csv_flatstructure -ID 'ID' -OutputFile 'OutputFile.csv' | clip" -ForegroundColor Yellow
        return
    }

    # Get the full path of the parent group
    $ParentGroup = Get-LMDeviceGroup -id $ID
    $ParentFullPath = $ParentGroup.fullPath

    # Function to display group details without indentation
    function Display-GroupDetails {
        param (
            [object]$Group
        )
        $GroupDetails = Get-LMDeviceGroup -id $Group.id | Select-Object name, fullPath, subGroups, appliesTo, description
        $GroupDetails | ForEach-Object {
            [PSCustomObject]@{
                GroupID     = $Group.id
                Name        = $_.name
                FullPath    = $_.fullPath
                AppliesTo   = $_.appliesTo
                Description = $_.description
            }
            if ($_.subGroups) {
                foreach ($subGroup in $_.subGroups) {
                    Display-GroupDetails -Group $subGroup
                }
            }
        }
    }

    # Collect all group details in a list
    $GroupList = @()

    # Display the parent group details
    $GroupList += [PSCustomObject]@{
        GroupID     = $Group.id
        Name        = $ParentGroup.name
        FullPath    = $ParentFullPath
        AppliesTo   = $_.appliesTo
        Description = $_.description
    }

    # Get all subgroups of the parent group
    $SubGroups = Get-LMDeviceGroup -id $ID | Select-Object -expandProperty subGroups

    # Iterate through each subgroup and collect relevant information without indentation
    foreach ($group in $SubGroups) {
        $GroupList += Display-GroupDetails -Group $group
    }

    # Output the group details to CSV
    if ($OutputFile) {
        $GroupList | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Folder tree exported to $OutputFile" -ForegroundColor Green
    } else {
        $GroupList | Format-Table
    }
}

#RUN: Print-FolderTree_2_csv_flatstructure -id 11234 -OutputFile 'Australia_Folders_flat.csv

#------------------------
function Start-Autodiscovery {
    [String]$groupid = $args[0]
    # checks for variable else shows example.
    if (-not $groupid['']) {
        Write-Host "Example usage: Start-Autodiscovery <id>" -ForegroundColor Yellow
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $groupid
    foreach ($item in  $devices.id) {
        Write-Host "$item"
        Get-LMDevice -displayName $item | Foreach-Object {Invoke-LMActiveDiscovery -id $_.id}
    }
}
#RUN: Start-Autodiscovery <id>


#------------------------
function Show-ClassRouterInTree {
    param (
        [int]$ParentId,
        [string]$OutputCsvPath
    )

    # Get the full path of the parent group
    $ParentGroup = Get-LMDeviceGroup -id $ParentId
    $ParentFullPath = $ParentGroup.fullPath

    # Function to display group details with indentation
    function Display-GroupDetails {
        param (
            [string]$Indent,
            [object]$Group
        )
        $GroupDetails = Get-LMDeviceGroup -id $Group.id | select name, fullPath, subGroups
        $GroupDetails | ForEach-Object {
            [PSCustomObject]@{
                Name     = "$Indent$($_.name)"
                FullPath = $_.fullPath
            }
            if ($_.subGroups) {
                foreach ($subGroup in $_.subGroups) {
                    Display-GroupDetails -Indent "$Indent    " -Group $subGroup
                }
            }
        }
    }

    # Collect all group details in a list
    $GroupList = @()

    # Display the parent group details
    $GroupList += [PSCustomObject]@{
        Name     = $ParentGroup.name
        FullPath = $ParentFullPath
    }

    # Get all subgroups of the parent group
    $SubGroups = Get-LMDeviceGroup -id $ParentId | select -expandProperty subGroups

    # Iterate through each subgroup and collect relevant information with indentation
    foreach ($group in $SubGroups) {
        $GroupList += Display-GroupDetails -Indent "    " -Group $group
        $devices = Get-LMDeviceGroupDevices -Id $group.Id
        foreach ($device in $devices) {
            # Get the custom property value
            $customProperty = $device.CustomProperties | Where-Object { $_.Name -eq 'ntt.class' }
            if ($customProperty.Value -eq "ip router") {
                $GroupList += [PSCustomObject]@{
                    Name           = "    $($device.DisplayName)"
                    FullPath       = $group.fullPath
                    CustomProperty = $customProperty.Value
                }
            }
        }
    }

    # Output the group details to a CSV file
    $GroupList | Export-Csv -Path $OutputCsvPath -NoTypeInformation
}

#RUN: Show-ClassRouterInTree -ParentId 12399 -OutputCsvPath "output.csv"

#------------------------
function Get-PortalInfo {
Get-LMPortalInfo |select nttanzairservicesuat

}
#RUN: Get-PortalInfo
#------------------------

function Show-Menu {
    param (
            [Parameter(Mandatory=$true)]
            [array]$data,
            [string]$filter
    )

    # If no filter is provided, display an example usage message
    if (-not $filter) {
            Write-Host "Example usage: Show-Menu -data `$menu -filter '.|device|collector|random'" -ForegroundColor Yellow
            return
    }

    # Filter the menu items if a filter is provided
    #$data = $data | Where-Object { $_.Name -match $filter } #case sensitive
	$data = $data | Where-Object { $_.Name -imatch $filter } #case insensitive

    # Display the menu using Format-SpectreTable
    $data | Format-SpectreTable -Title "LM Functions"
}
#RUN: Show-Menu -data $menu -filter .
#RUN: Show-Menu -data $menu -filter "random" # to just show words with RANDOM

#------------------------
#Get a list of Instanes for all devices for a customer
function Show-GroupDeviceCounts {
<#
.SYNOPSIS
    This will show the datasource and instance count for a device group

.DESCRIPTION
    This will show the datasource and instance count for a device group.
    Will to a print:  
      DeviceName = $device.displayName
      Count_of_dataSourceName = $Count_of_dataSourceName
      Count_of_instanceNumber = $Count_of_instanceNumber

.PARAMETER GroupId
    The group used to collect a list of devices

.PARAMETER OutputFileName
    The name of the output file

.INPUTS
    GroupId        - Used as the selection of device
    OutputFileName - ./path/filename to save the csv file.
.EXAMPLE
    Show-GroupDeviceCounts -GroupId $GroupId -OutputFileName $OutputFileName

.NOTES

#>    
    param (
        [Parameter(Mandatory=$true)]
        [int]$GroupId,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputFileName
    )
    
    # Get the list of devices in the group
    #$devices = Get-LMDeviceGroupDevices -Id $GroupId  -IncludeSubGroups $True #Watch this, if someone adds the parent, it could go nuts
    $devices = Get-LMDeviceGroupDevices -Id $GroupId

    # Initialize an array to store the results
    $results = @()

    # Initialize the progress counter
    $totalDevices = $devices.Count
    $currentDevice = 0

    # Loop through each device in the group
    foreach ($device in $devices) {
        # Update the progress counter
        $currentDevice++
        Write-Progress -Activity "Processing Devices" -Status "Processing $currentDevice of $totalDevices" -PercentComplete (($currentDevice / $totalDevices) * 100)
        
        # Retry logic
        $maxRetries = 3
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                # Get the list of datasources for the device
                $DataSources = Get-LMDeviceDatasourceList -id $device.id | select dataSourceName, instanceNumber
                
                # Count the totals
                $Count_of_dataSourceName = ($DataSources | group dataSourceName).Count
                $Count_of_instanceNumber = ($DataSources | measure instanceNumber -Sum).Sum
                
                # Capture the ntt.class value from customProperties
                $nttClass = $device.CustomProperties | Where-Object { $_.Name -eq 'ntt.class' }
                
                
                # Create a custom object to store the results
                $result = [PSCustomObject]@{
                    DeviceName = $device.displayName
                    Count_of_dataSourceName = $Count_of_dataSourceName
                    Count_of_instanceNumber = $Count_of_instanceNumber
                    NTTClass = $nttClass.Value
                }
                
                # Add the result to the array
                $results += $result
                
                # Mark as success
                $success = $true
            } catch {
                Write-Warning "Failed to process device $($device.displayName). Attempt $($retryCount + 1) of $maxRetries."
                $retryCount++
                Start-Sleep -Seconds 5 # Wait before retrying
            }
        }
        
        if (-not $success) {
            Write-Error "Failed to process device $($device.displayName) after $maxRetries attempts."
        }
    }

    # Export the results to a CSV file
    $results | Export-Csv -Path $OutputFileName -NoTypeInformation
}
# Example usage:
#RUN: Show-GroupDeviceCounts -GroupId 123 -OutputFileName "DeviceDataSources.csv"

#------------------------
function Show-DeviceData {
    param (
        [string]$displayName
    )

    if (-not $displayName) {
        Write-Host "Please provide a display name. Example usage: Show-DeviceData -displayName SAMPLE" -ForegroundColor Yellow
        return
    }

    try {
        $device = Get-LMDevice -displayName $displayName
        if (-not $device) {
            Write-Host "Device not found." -ForegroundColor Red
            return
        }

        $DataSources = Get-LMDeviceDatasourceList -id $device.id | select dataSourceName, instanceNumber
        $Count_of_dataSourceName = ($DataSources | group dataSourceName).Count
        $Count_of_instanceNumber = ($DataSources | measure instanceNumber -Sum).Sum

        $nttClass                  = $device.CustomProperties    | Where-Object { $_.Name -eq 'ntt.class' }
        $CustomWMI                 = $device.CustomProperties    | Where-Object { $_.Name -eq 'wmi.user' }
        $Categories                = $device.CustomProperties    | Where-Object { $_.Name -eq 'system.categories' }
        $inheritedProp_wmi         = $device.inheritedProperties | Where-Object { $_.Name -eq 'wmi.user' }
        $autoProperties_wmi_state  = $device.autoProperties      | Where-Object { $_.Name -eq 'auto.wmi.operational' }
        $inheritedProp_snmp        = $device.inheritedProperties | Where-Object { $_.Name -eq 'snmp.community' }
        $autoProperties_snmp_state = $device.autoProperties      | Where-Object { $_.Name -eq 'auto.snmp.operational.ntt' }

        $inheritedProperty_wmi = if ($inheritedProp_wmi) { "TRUE" } else { "N/A" }
        $inheritedProperty_snmp = if ($inheritedProp_snmp) { "TRUE" } else { "N/A" }

        # Export inherited WMI properties to CSV if applicable
        if ($inheritedProperty_wmi -eq "TRUE") {
            $wmiInherited = Get-LMDeviceProperty -Id $device.id | Where-Object { $_.name -like '*wmi.user*' }
            #$wmiInherited.inheritList | Select-Object value, fullpath | Export-Csv -Path "$displayName`_WMI_Inherited.csv" -NoTypeInformation
            $inheritedProp_wmi_fullpath = $wmiInherited.inheritList | Select-Object fullpath
        }

        # Export inherited SNMP properties to CSV if applicable
        if ($inheritedProperty_snmp -eq "TRUE") {
            $snmpInherited = Get-LMDeviceProperty -Id $device.id | Where-Object { $_.name -like '*snmp*' }
            #$snmpInherited.inheritList | Select-Object value, fullpath | Export-Csv -Path "$displayName`_SNMP_Inherited.csv" -NoTypeInformation
            $inheritedProperty_snmp_fullpath = $snmpInherited.inheritList | Select-Object fullpath
        }

        [PSCustomObject]@{
            DisplayName                      = $displayName
            DeviceID                         = $device.id
            DataSourceCount                  = $Count_of_dataSourceName
            InstanceNumberSum                = $Count_of_instanceNumber
            NTTClass                         = $nttClass.Value
            CustomWMI                        = $CustomWMI.Value
            inheritedProperty_wmi            = $inheritedProperty_wmi
            inheritedProp_wmi                = $inheritedProp_wmi.Value
            inheritedProp_wmi_fullpath       = $inheritedProp_wmi_fullpath.fullpath
            autoProperties_wmi_state         = $autoProperties_wmi_state.Value
            inheritedProperty_snmp           = $inheritedProperty_snmp
            inheritedProp_snmp               = $inheritedProp_snmp.Value
            autoProperties_snmp_state        = $autoProperties_snmp_state.Value
            inheritedProperty_snmp_fullpath  = $inheritedProperty_snmp_fullpath.fullpath
            Categories                       = $Categories.Value
        }
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}
#RUN: Show-DeviceData -displayName SAMPLE

#------------------------
function Show-DeviceData_group {
    <#
    .SYNOPSIS
        Shows the count of Datasource and Instances for all devices in a specified group.

    .DESCRIPTION
        This function retrieves and displays the count of Datasource and Instances for all devices in a specified group.

    .PARAMETER groupId
        The ID of the device group to query.

    .PARAMETER csvFileName
        The name of the CSV file to write the results to.

    .INPUTS
        groupId - The ID of the device group.
        csvFileName - The name of the CSV file.

    .EXAMPLE
        Show-DeviceData_group -groupId 2122 -csvFileName "DeviceData.csv"

    .NOTES
    #>
    param (
        [int]$groupId,
        [string]$csvFileName = "DeviceData.csv"
    )

    if (-not $groupId) {
        Write-Host "Please provide a group ID. Example usage: Show-DeviceData_group -groupId 2122 -csvFileName 'DeviceData.csv'" -ForegroundColor Yellow
        return
    }

    # Initialize an array to store the results
    $results = @()

    try {
        # Get the devices in the specified group
        $devices = Get-LMDeviceGroupDevices -id $groupId | select displayName

        if (-not $devices) {
            Write-Host "No devices found in the specified group." -ForegroundColor Red
            return
        }

        # Initialize progress bar
        $totalDevices = $devices.Count
        $counter = 0

        # Iterate through each device and output the display name
        foreach ($device in $devices) {
            $counter++
            $percentComplete = ($counter / $totalDevices) * 100
            Write-Progress -Activity "Processing devices" -Status "Processing $counter of $totalDevices" -PercentComplete $percentComplete

            $result = Show-DeviceData -displayName $device.displayName
            $results += $result
        }

        # Export the results to a CSV file
        $results | Export-Csv -Path $csvFileName -NoTypeInformation
        Write-Host "Data exported to $csvFileName" -ForegroundColor Green
    } catch {
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}

#RUN: Show-DeviceData_group -groupId 2122 -csvFileName "DeviceData.csv"

#------------------------
function Show-ERI {
    param (
        [string]$DisplayName
    )

    if (-not $DisplayName) {
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host "Show-ERI -DisplayName 'nw-backup'" -ForegroundColor Yellow
        return
    }

    $items = Get-LMDevice -DisplayName $DisplayName

    foreach ($item in $items) {
        $autoProperties     = $item | Select-Object -ExpandProperty autoProperties
        $custProperties     = $item | Select-Object -ExpandProperty customProperties
        $predefResourceType = ($autoProperties | Where-Object { $_.Name -eq 'predef.externalResourceID' }).Value
        $inboundERI         = ($custProperties | Where-Object { $_.Name -eq 'manual.inbound.externalResourceID' }).Value
        $outboundERI        = ($custProperties | Where-Object { $_.Name -eq 'manual.outbound.externalResourceID' }).Value

        [PSCustomObject]@{
            DisplayName        = $item.DisplayName
            DeviceName         = $item.Name
            InboundERI         = $inboundERI
            OutboundERI        = $outboundERI
            PredefResourceType = $predefResourceType
        }
    }
}
# RUN: Show-ERI -DisplayName 'nw-backup
#------------------------
function Set-ERI {
    param (
        [Parameter(Mandatory=$false)][string]$DisplayName,
        [Parameter(Mandatory=$false)][string]$INERI,
        [Parameter(Mandatory=$false)][string]$OUTERI
)


    if (-not $DisplayName -or -not $INERI -or -not $OutERI) {
        Write-Host "Example: Set-ERI -DisplayName 'MyDevice01' -INERI 'local:mac,remote:mac' -OUTERI 'local:mac,remote:mac'" -ForegroundColor Yellow
        return
    }

    $device = Get-LMDevice -DisplayName $DisplayName

    if (-not $device) {
        Write-Error "Device with display name '$DisplayName' not found."
        return
    }

    $device | Set-LMDevice -Properties @{ 'manual.inbound.externalResourceID' = $INERI } | Out-Null
    $device | Set-LMDevice -Properties @{ 'manual.outbound.externalResourceID' = $OUTERI } | Out-Null
}

# RUN: Set-ERI -DisplayName 'MyDevice01' -INERI 'abc-123-xyz'


#------------------------
<#
.SYNOPSIS
    LogicMonitor audit devices in a group for key fields.

.DESCRIPTION
    LogicMonitor audit devices in a group for key fields.
	Output to a csv with the order set in $propertyOrder


.EXAMPLE
    PS> pwsh -File "Export-LMDeviceAudit -FullPath "ESV/All" -OutputPath "C:\Reports\ESV_Audit.csv"

.NOTES
    Version 1.0

#>
function Export-LMDeviceAudit {
    [CmdletBinding()]
    param (
        [string]$FullPath,
        [string]$OutputPath
    )

    if (-not $FullPath -or -not $OutputPath) {
        Write-Host "`nExample usage:" -ForegroundColor Yellow
        Write-Host 'Export-LMDeviceAudit -FullPath "ESV/All" -OutputPath "C:\Reports\ESV_Audit.csv"' -ForegroundColor Yellow
        return
    }

    # Get a list of devices in the specified device group
    $groupId = (Get-LMDeviceGroup -filter "fullPath -eq '$FullPath'").id
    Write-Host "GroupId is: $($groupId)"

    $devices = Get-LMDeviceGroupDevices -Id $groupId
    Write-Host "Device count is: $($devices.count)"

    $outputData = @{}

    foreach ($item in $devices) {
        $systemProperties = $item | Select-Object -ExpandProperty systemProperties
        $autoProperties   = $item | Select-Object -ExpandProperty autoProperties
        $customProperties = $item | Select-Object -ExpandProperty customProperties

        $sysoid        = ($systemProperties | Where-Object { $_.Name -eq 'system.sysoid' }).Value
        $sysinfo       = ($systemProperties | Where-Object { $_.Name -eq 'system.sysinfo' }).Value
        $hoststatus    = ($systemProperties | Where-Object { $_.Name -eq 'system.hoststatus' }).Value
        $wmiResp       = ($autoProperties   | Where-Object { $_.Name -eq 'auto.ntt.wmi.responding' }).Value
        $wmiExc        = ($autoProperties   | Where-Object { $_.Name -eq 'auto.ntt.wmi.exception' }).Value
        $snmpOperExc   = ($autoProperties   | Where-Object { $_.Name -eq 'auto.ntt.snmp.exception' }).Value
        $NTTsnmpRes    = ($autoProperties   | Where-Object { $_.Name -eq 'auto.ntt.snmp.responding' }).Value
        $MonLevel      = ($customProperties | Where-Object { $_.Name -eq 'ntt.monitoring.level' }).Value
        $nttclass      = ($customProperties | Where-Object { $_.Name -eq 'ntt.class' }).Value
        $nttcompany    = ($customProperties | Where-Object { $_.Name -eq 'ntt.company' }).Value
        $nttasatypeapp = ($customProperties | Where-Object { $_.Name -eq 'ntt.asa.type.app' }).Value
        $wmiuser       = ($customProperties | Where-Object { $_.Name -eq 'wmi.user' }).Value
        $snmpuser      = ($customProperties | Where-Object { $_.Name -eq 'snmp.security' }).Value
        $location      = ($customProperties | Where-Object { $_.Name -eq 'location' }).Value
        $locationState = ($customProperties | Where-Object { $_.Name -eq 'location.state' }).Value
        $snmpversion   = ($customProperties | Where-Object { $_.Name -eq 'snmp.version' }).Value

        $fullMonitoring = (
            ($wmiResp -ne $null -and $wmiResp.Contains("true")) -or
            ($NTTsnmpRes -ne $null -and $NTTsnmpRes.Contains("true"))
        )

        $deviceData = @{
            'ntt.class'            = $nttclass
            'ntt.company'          = $nttcompany
            'ntt.asa.type.app'     = $nttasatypeapp
            'Location'             = $location
            'State '               = $locationState
            'sysoid'               = $sysoid
            'sysinfo'              = $sysinfo
            'hoststatus'           = $hoststatus
            'snmp.security'        = $snmpuser
            'snmp.responding'      = $NTTsnmpRes
            'snmp.exception'       = $snmpOperExc
            'snmp.version '        = $snmpversion
            'wmi.user'             = $wmiuser
            'wmi.responding'       = $wmiResp
            'wmi.exception'        = $wmiExc
            'monitoring.level'     = $MonLevel
            'fullMonitoring'       = $fullMonitoring
        }

        $outputData[$item.displayName] = $deviceData
    }

    $propertyOrder = @(
        'ntt.class',
        'ntt.company',
        'ntt.asa.type.app',
        'Location',
        'State ',
        'sysoid',
        'sysinfo',
        'hoststatus',
        'snmp.security',
        'snmp.responding',
        'snmp.exception',
        'snmp.version ',
        'wmi.user',
        'wmi.responding',
        'wmi.exception',
        'monitoring.level',
        'fullMonitoring'
    )

    $csvData = @()
    foreach ($deviceName in $outputData.Keys) {
        $row = [PSCustomObject]@{
            DisplayName = $deviceName
        }
        foreach ($propertyName in $propertyOrder) {
            $row | Add-Member -MemberType NoteProperty -Name $propertyName -Value $outputData[$deviceName][$propertyName]
        }
        $csvData += $row
    }

    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Export complete: $OutputPath"
}

#RUN: 'Export-LMDeviceAudit -FullPath "ESV/All" -OutputPath "C:\Reports\ESV_Audit.csv"'
#------------------------

function Export-CPUInstanceCounts {
	 <#
    .SYNOPSIS
        Shows the count of Datasource and Instances on devices in a group filtered to CPU|Processor

    .DESCRIPTION
        Shows the count of Datasource and Instances on devices in a group filtered to CPU|Processor

    .PARAMETER groupId
        The ID of the device group to query.

    .PARAMETER csvFileName
        The name of the CSV file to write the results to.

    .INPUTS
        groupId - The ID of the device group.
        OutputFile - The name of the CSV file.

    .EXAMPLE
        Export-CPUInstanceCounts -GroupId 9766 -OutputFile 'CPU_InstanceCounts.csv'

    .NOTES
    #>
    param (
        [int]$GroupId,
        [string]$OutputFile
    )

    if (-not $GroupId -or -not $OutputFile) {
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host "Export-CPUInstanceCounts -GroupId 9766 -OutputFile 'CPU_InstanceCounts.csv'" -ForegroundColor Yellow
        return
    }

    try {
        # Get all devices in the group
        $Devices = Get-LMDeviceGroupDevices -Id $GroupId
    } catch {
        Write-Host "Failed to retrieve devices for GroupId $GroupId. Error: $_" -ForegroundColor Red
        return
    }

    $OutputRows = @()
    $TotalDevices = $Devices.Count
    $CurrentIndex = 0

    foreach ($Device in $Devices) {
        $CurrentIndex++
        Write-Progress -Activity "Processing Devices" -Status "Device: $($Device.displayName)" -PercentComplete (($CurrentIndex / $TotalDevices) * 100)

        try {
            $DataSourceFull = Get-LMDeviceDatasourceList -id $Device.id
        } catch {
            Write-Host "Failed to get datasources for device $($Device.displayName). Error: $_" -ForegroundColor Red
            continue
        }

        $DataSourcesCPU = $DataSourceFull | Where-Object {
            $_.dataSourceName -match "CPU|Processor" -or $_.dataSourceDisplayName -match "CPU|Processor"
        }

        $DeviceRow = [PSCustomObject]@{
            Device = $Device.displayName
        }

        foreach ($ds in $DataSourcesCPU) {
            try {
                $Instances = Get-LMDeviceDatasourceInstance -DatasourceId $ds.datasourceId -DeviceId $Device.id
                $DeviceRow | Add-Member -MemberType NoteProperty -Name $ds.dataSourceName -Value $Instances.Count
            } catch {
                Write-Host "Failed to get instances for datasource $($ds.dataSourceName) on device $($Device.displayName). Error: $_" -ForegroundColor Red
                $DeviceRow | Add-Member -MemberType NoteProperty -Name $ds.dataSourceName -Value "Error"
            }
        }

        $OutputRows += $DeviceRow
    }

    try {
        $OutputRows | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Export complete: $OutputFile" -ForegroundColor Green
    } catch {
        Write-Host "Failed to export CSV to $OutputFile. Error: $_" -ForegroundColor Red
    }
}

# RUN: Export-CPUInstanceCounts -GroupId 9766 -OutputFile 'CPU_InstanceCounts.csv'
#------------------------
function Magic8Ball {
    $responses = @(
        "It is certain",
        "It is decidedly so",
        "Without a doubt",
        "Yes, definitely",
        "You may rely on it",
        "As I see it, yes",
        "Most likely",
        "Outlook good",
        "Yes",
        "Signs point to yes",
        "Reply hazy, try again",
        "Ask again later",
        "Better not tell you now",
        "Cannot predict now",
        "Concentrate and ask again",
        "Don't count on it",
        "My reply is no",
        "My sources say no",
        "Outlook not so good",
        "OMG....What are you thinking!",
        "Very doubtful"
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $responses.Length
    return $responses[$randomIndex] | Format-SpectreTable -Title "I have read your mind and answered below."
}
#RUN: Magic8Ball
#------------------------
function RockPaperScissors {
    $responses = @(
        "Rock",
        "Paper",
        "Scissors"
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $responses.Length
    return $responses[$randomIndex] | Format-SpectreTable -Title "Can you even play this alone?"
}
#RUN: RockPaperScissors
#------------------------
function quotes {
    $responses = @(
        "To walk out on a limb, I must trust the tree, the wind, and myself.",
        "I am unburdened, i know I cannot change the event of pass",
        "Tomorrow is a mountain built with the rocks of today",
        "I am patient. Observation is the key to victory.",
        "I seek peace of mind. Anger dulls my senses.",
        "I will be courageous. Fly forward like a dragonfly.",
        "Fearing the rainstorm will not prevent the flood.",
        "I am an ember, fanned by the flames of purpose."
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $responses.Length
    return $responses[$randomIndex] | Format-SpectreTable -Title "My helpful quotes."
}
#RUN: quotes
#------------------------
function jokes {
    $responses = @(
        "Why did the network admin cross the road?`nTo check if the other side had better uptime.",
        "Why do network monitoring tools never get invited to parties?`nBecause they always bring up dropped connections.",
        "How many network engineers does it take to change a light bulb?`nNone. That’s a hardware issue—they just monitor the darkness.",
        "What’s a network admin’s favorite game?`nPacket capture the flag.",
        "I tried to start a band called: 1024 Mbps.`nBut we couldn’t get a gig.",
        "Why don’t network engineers play hide and seek?`nBecause good luck hiding when they’ve got traceroute.",
        "What’s a network admin’s favorite pickup line?`nYou auto-negotiated your way right into my heart.",
        "Why was the network cable always calm?`nBecause it knew how to stay grounded.",
        "My network went down for five minutes.`nI had to talk to my family. They seem like nice people.",
        "Why did the DHCP server get promoted?`nBecause it always knew how to assign responsibility.",
        "Why did the SNMP trap go to therapy?`nIt couldn’t handle all the alerts anymore."
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $responses.Length
    return $responses[$randomIndex] | Format-SpectreTable -Title "An IT monitoring joke"
}


#------------------------
function movies {
    $responses = @(
        "I am a leaf on the wind",
        "May the Force be with you",
        "Tomorrow is a mountain built with the rocks of today",
        "There's no place like home",
        "I'm gonna make him an offer he can't refuse",
        "You're gonna need a bigger boat",
		"I picked the wrong week to stop sniffing glue",
		"These are not the droids you are looking for",
        "Toto, I've a feeling we're not in Kasas anymore.",
        "Hello. My name is Inigo Montoya. You killed my father. Prepare to die..",
        "Nobody puts Baby in a corner",
        "All work and no play makes Jack a dull boy",
        "All right, Mr DeMille, I'm ready for my close-up"
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $responses.Length
    return $responses[$randomIndex] | Format-SpectreTable -Title "My helpful movie quotes."
}
#RUN: movies

#------------------------
function Show-ABCG {
    Get-LMCollectorGroup -Filter "autoBalance -eq 'True'" | Select-Object ID, Name, Description
}
#RUN: Show-ABCG

#------------------------
function Show-ABCG {
    param (
        [string]$filter
    )
    Get-LMCollectorGroup -Filter "autoBalance -eq 'True'" | Where-Object { $_.Name -match $filter } | Select-Object ID, Name, Description
}
#RUN: Show-ABCG or Show-ABCG -filter KPMG
#------------------------
function Update-ABCG {
    param (
        [string]$CollectorGroupName,
        [int]$TargetCollectorGroupId
    )

    # Get the collector group
    $ABCG = Get-LMCollector -filter "collectorGroupName -eq $CollectorGroupName"
    $ABCGid = $ABCG.collectorGroupId | select -first 1

    # Get all collectors in the group
    $collectors = $ABCG.id
    $totalCollectors = $collectors.Count
    $currentCollector = 0

    foreach ($LMCollector in $collectors) {
        $currentCollector++
        Write-Progress -Activity "Processing Collectors" -Status "Collector $currentCollector of $totalCollectors" -PercentComplete (($currentCollector / $totalCollectors) * 100)

        # Get devices for the current collector
        $devices = Get-LMDevice -Filter "currentCollectorId -eq $LMCollector" | Where-Object { $_.displayName -notlike "NW-LM-KPMG*" }
        $totalDevices = $devices.Count
        $currentDevice = 0

        foreach ($device in $devices) {
            $currentDevice++
            Write-Progress -Activity "Processing Devices" -Status "Device $currentDevice of $totalDevices" -PercentComplete (($currentDevice / $totalDevices) * 100)

            $deviceDetails = Get-LMDevice -displayname $device.displayname | Select-Object displayname, autoBalancedCollectorGroupId
            if ($deviceDetails.autoBalancedCollectorGroupId -ne $ABCGid) {
                Write-Output "Fixing: $deviceDetails.displayname"
                Get-LMDevice -displayname $deviceDetails.displayname | Set-LMDevice -AutoBalancedCollectorGroupId $TargetCollectorGroupId > $null
            }
        }
    }
}

#RUN: Update-ABCG -CollectorGroupName 'KPMG Collector Group' -TargetCollectorGroupId 52

#------------------------
function Show_device_by_siteid {
    param (
    [string]$siteId
)

if ([string]::IsNullOrEmpty($siteId)) {
    Write-Host "Usage: Show_device_by_siteid -siteId <siteId>" -ForegroundColor Yellow
    return
} 
$filter = "customProperties -eq $($('{"name":"ntt.site.id","value":"' + $siteId + '"}' | ConvertTo-Json))"
}
#RUN: Show_device_by_siteid -siteId '5740'

#------------------------
function Export-DeviceGroupAudit {
    param (
        [int]$GroupId,
        [string]$OutputPath = "Audit_Group_for_DS_and_Instances.csv"
    )

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
            'ntt.class'          = ($customProperties | Where-Object { $_.Name -eq 'ntt.class' }).Value
            'ntt.class.report'   = ($customProperties | Where-Object { $_.Name -eq 'ntt.class.report' }).Value
            'monitoring.level'   = ($customProperties | Where-Object { $_.Name -eq 'ntt.monitoring.level' }).Value
            'system.categories'  = ($customProperties | Where-Object { $_.Name -eq 'system.categories' }).Value
        }

        $datasources = Get-LMDeviceDatasourceList -id $item.id |
            Select-Object dataSourceName, instanceNumber |
            Where-Object { $_.instanceNumber -gt 0 -and $_.dataSourceName -notlike "*LogicMonitor_Collector*" } |
            Sort-Object dataSourceName

        foreach ($ds in $datasources) {
            $deviceData[$ds.dataSourceName] = $ds.instanceNumber
        }

        $outputData[$item.displayName] = $deviceData
    }

    $csvData = @()
    foreach ($deviceName in $outputData.Keys) {
        $row = [PSCustomObject]@{ DisplayName = $deviceName }
        foreach ($propertyName in $outputData[$deviceName].Keys) {
            $row | Add-Member -MemberType NoteProperty -Name $propertyName -Value $outputData[$deviceName][$propertyName]
        }
        $csvData += $row
    }

    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
}

#RUN: Export-DeviceGroupAudit -GroupId 4791 -OutputPath 'C:\Reports\GroupAudit.csv'


#------------------------
function Show-AP_Instances_on_WLC {
    param (
        [string]$DeviceNameFilter = "*virtual*",
        [string]$OutputPath = $("Woolies_AP_" + (Get-Date -Format "ddMMyyyy") + ".csv")
    )

    $Devices = Get-LMDevice -DisplayName $DeviceNameFilter
    $Results = @()

    foreach ($Device in $Devices) {
        $DataSource = Get-LMDeviceDatasourceList -id $Device.id | Where-Object { $_.dataSourceName -eq "NTT_PingCiscoAP-" }
        if ($DataSource) {
            $Instances = Get-LMDeviceDatasourceInstance -DatasourceId $DataSource.datasourceId -DeviceId $Device.id
            foreach ($i in $Instances) {
                if ($i.stopMonitoring -eq $true -or $i.disableAlerting -eq $true) {
                    $Results += [PSCustomObject]@{
                        DeviceName        = $Device.displayName
                        Name              = $i.Name
                        groupName         = $i.groupName
                        deviceDisplayName = $i.deviceDisplayName
                        wildValue         = $i.wildValue
                        sdtStatus         = $i.sdtStatus
                        disableAlerting   = $i.disableAlerting
                        stopMonitoring    = $i.stopMonitoring
                        Id                = $i.id
                    }
                }
            }
        }
    }

    $Results | Export-Csv -NoTypeInformation -Path $OutputPath
    Write-Host "Results exported to $OutputPath"
}

#RUN: Show-AP_Instances_on_WLC
#RUN: Show-AP_Instances_on_WLC -DeviceNameFilter "*virtual*" -OutputPath "Custom_AP_Report.csv"
#RUN: Show-AP_Instances_on_WLC -DeviceNameFilter "*mist*" -OutputPath "Custom_AP_Report.csv"
#------------------------
function Search-KeywordInFiles {
    param (
        [string]$Keyword,
        [string]$Path
    )

    # Escape special characters in the keyword
    $escapedKeyword = [regex]::Escape($Keyword)
	Write-Output "EscapedKeyword: $escapedKeyword" -ForegroundColor Yellow
    $found = $false

    Get-ChildItem -Path $Path -Recurse -File | ForEach-Object {
        $fileContent = Get-Content -Path $_.FullName
        $fileContent | ForEach-Object {
            if ($_ -match $escapedKeyword) {
                Write-Output "Keyword found in file: $($_.FullName)"
                Write-Output "Details: $_"
                $found = $true
            }
        }
    }

    if (-not $found) {
        Write-Output "No results found for $Keyword" -ForegroundColor Yellow
    }
}

#RUN: Search-KeywordInFiles -Keyword "your.Keyword" -Path "C:\your\path"
    
#------------------------
function Send-Email {
    param (
        [string]$To,
        [string]$Subject,
        [string]$Body,
        [string]$Attachment
    )

    # Check if required parameters are provided
    if (-not $Subject -or -not $Body -or -not $Attachment) {
        Write-Host "Example usage of Send-Email -To 'ryan.gillan@nttdata.com' -Subject 'Subject' -Body 'Body' -Attachment 'C:\temp\services\WOW_services.csv'" -ForegroundColor Yellow
        return
    }

    # Create Outlook COM object
    $Outlook = New-Object -ComObject Outlook.Application
    # Create a new mail item
    $Mail = $Outlook.CreateItem(0)

    # Set email properties
    $Mail.To      = $To
    $Mail.Subject = $Subject
    $Mail.Body    = $Body

    # Add attachment
    $Mail.Attachments.Add($Attachment)

    # Send the email
    $Mail.Send()

    # Clean up
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Outlook) | Out-Null
}

#RUN: Send-Email -To "ryan.gillan@nttdata.com" -subject "Subject" -Body "Body" -Attachment "C:\temp\services\WOW_services.csv"


#------------------------
function Get-LmAlertbytype {
    param (
        [int]$DaysBack = 1,
        [string]$InstanceFilter = "Juniper_Mist_AP_Health",
        [string]$ExportPath = ""
    )

    # Define start and end dates
    $startDate = (Get-Date).AddDays(-$DaysBack)
    $endDate = Get-Date

    # Get alerts using date range, type, and severity filter
    $LMServiceAlerts = Get-LMAlert -ClearedAlerts $true -Type dataSourceAlert -StartDate $startDate -EndDate $endDate -Severity Critical | Where-Object {
        $_.instanceName -eq $InstanceFilter
    }

    # Return selected properties with converted epoch times
    $filteredAlerts = foreach ($alert in $LMServiceAlerts) {
        [PSCustomObject]@{
            resourceId        = $alert.resourceId
            startDateTime     = ([System.DateTimeOffset]::FromUnixTimeSeconds($alert.startEpoch)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            endDateTime       = ([System.DateTimeOffset]::FromUnixTimeSeconds($alert.endEpoch)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            startEpoch        = $alert.startEpoch
            endEpoch          = $alert.endEpoch
            type              = $alert.type
            internalId        = $alert.internalId
            monitorObjectName = $alert.monitorObjectName
            dataPointName     = $alert.dataPointName
            instanceName      = $alert.instanceName
        }
    }

    # Export to CSV if path is provided
    if ($ExportPath -ne "") {
        $filteredAlerts | Export-Csv -Path $ExportPath -NoTypeInformation
    }

    return $filteredAlerts
}
# Get alerts from the last 2 days for instances equalto: "Juniper_Mist_AP_Health"
#RUN: Get-LmAlertbytype -DaysBack 2 -InstanceFilter "Juniper_Mist_AP_Health"


# Export results to CSV
#Get-LmAlertbytype -DaysBack 2 -InstanceFilter "Juniper_Mist_AP_Health" -ExportPath "MistHealthAlerts.csv"
#------------------------
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

#------------------------
#------------------------

#Write-Host "LM custom functions: -ForegroundColor Yellow
#Show the functions in this file.
#Get-Content "C:\Users\rgillan\OneDrive - NTT\Documents\LogicMonitor\lm-functions.ps1" | Where-Object { $_ -match "^function" }

#Show the functions in this file.
#$functions = Get-Content "C:\Users\rgillan\OneDrive - NTT\Documents\LogicMonitor\lm-functions.ps1" | Where-Object { $_ -match "^function" } | ForEach-Object { $_ -replace "^function\s+|\s*{", "" } | Sort-Object
# Write-Host "LM custom functions:" -ForegroundColor Yellow
#foreach ($function in $functions) {
#    Write-Host $function -ForegroundColor Yellow
#}


#Print messages
#Write-Host "LM custom functions: `n Show-Dead (Company_name), Show-Devices (Company_name), Dead-Collectors (Company_name), Show-folders, Show-GroupTree, Show-Country-folders, Get-CurrentDate, Show-DataSources, Show-DataSources-full, Show-Data `n )" -ForegroundColor Yellow
#Write-Host " continued: `n Get-GroupDetails (ID), Show-Collectors, Get-GroupDetails_to_csv,  Show-MissingSSIDPrompt, Generate-RandomPassword" -ForegroundColor Yellow

# TO DO: Add tags and some way to filter on these.
#         eg Collector.  add a command to show the functions where only contains tag Collector.
$menu = @(
    [pscustomobject]@{Name="Show-Menu"; Overview="Show this menu"; Example="Show-Menu -data `$menu -filter '<.|Collector|devices>'"},
    [pscustomobject]@{Name="Show-random"; Overview="Show a random person"; Example="Show-random"},
    [pscustomobject]@{Name="Magic8Ball"; Overview="Runs a Magic-8-Ball"; Example="Magic8Ball"},
    [pscustomobject]@{Name="RockPaperScissors"; Overview="Runs a Rock Paper Scissors game"; Example="RockPaperScissors"},
    [pscustomobject]@{Name="Quotes"; Overview="Provides helpful Quotes from Assasins Creed."; Example="Quotes"},
    [pscustomobject]@{Name="Movies"; Overview="Provides helpful Quotes from Movies."; Example="Movies"},
    [pscustomobject]@{Name="Search-KeywordInFiles"; Overview="Search like grep."; Example="Search-KeywordInFiles -Keyword 'yourKeyword' -Path 'C:\your\path'"},
	[pscustomobject]@{Name="Send-Email"; Overview="Sends email thru Outlook."; Example="Send-Email -To 'ryan.gillan@nttdata.com' -subject 'Subject' -Body 'Body' -Attachment 'C:\temp\services\WOW_services.csv'"},
	
    [PSCustomObject]@{Name = "__"; Overview = "__";Example="__" }, # Blank line
    [pscustomobject]@{Name="Show_BackupConfig"; Overview="Show backup configs"; Example="Show_BackupConfig -displayname 'displayname'"},
    [pscustomobject]@{Name="Show-Dead"; Overview="Show dead devices after entering the company (ntt.company value)"; Example="Show-Dead 'CHED'"},
    [pscustomobject]@{Name="Show-Devices"; Overview="Show devices on a company"; Example="Show-Devices 'CHED'"},
    [pscustomobject]@{Name="Show-DeadCollectors"; Overview="Show Dead Collectors on a company"; Example="Show-DeadCollectors"},
    [pscustomobject]@{Name="Show-Collectors"; Overview="Show Collectors on a company"; Example="Show-Collectors"},
    [pscustomobject]@{Name="Show-folders"; Overview="Show LM root folders"; Example="Show-folders"},
    [pscustomobject]@{Name="Show-Country-folders"; Overview="Show Country folders and host count"; Example="Show-Country-folders -fullPath 'NTT-AU'"},
    [pscustomobject]@{Name="Show-Country-folders_plus_DEAD"; Overview="Show Country folders, host and dead count"; Example="Show-Country-folders_plus_DEAD -fullPath 'NTT-AU'"},
    [pscustomobject]@{Name="Show-Country-Show-Country-folders_plus_DEAD"; Overview="Show Country folders, host and dead count. Email output"; Example="Show-Country-folders_plus_DEAD_v2 -fullPath 'NTT-AU' -EmailTo 'ryan.gillan@nttdata.com'"},
    [pscustomobject]@{Name="Show-GroupTree"; Overview="Show folders in a tree"; Example="Show-GroupTree '5000'"},
    [pscustomobject]@{Name="Print-FolderTree_2_csv"; Overview="Print-FolderTree_2_csv"; Example="Print-FolderTree_2_csv -id 11234 -OutputFile 'Australia_Folders.csv' "},
    [pscustomobject]@{Name="Print-FolderTree_2_csv_flatstructure"; Overview="Print-FolderTree_2_csv without indents. Shows folder,path and appliesto"; Example="Print-FolderTree_2_csv_flatstructure -id 11234 -OutputFile 'Australia_Folders_flat.csv' "},
    [pscustomobject]@{Name="Show-Roles"; Overview="Show roles on the portal"; Example="Show-Roles "},
    [pscustomobject]@{Name="Show-Users"; Overview="Show users on the portal"; Example="Show-Users "},
    [pscustomobject]@{Name="Show-DeviceOnCollector"; Overview="Show Devices running on Collector 'XX'"; Example="Show-DeviceOnCollector -collector '<collectorId>'"},
    [pscustomobject]@{Name="Show-Devices_in_group"; Overview="Show-Devices_in_group"; Example="Show-Devices_in_group 'ID'"},
    [pscustomobject]@{Name="Show-DataSources"; Overview="Show-DataSource"; Example="Show-DataSources 'ss-core'"},
    [pscustomobject]@{Name="Show-DataSources-full"; Overview="Show-DataSources-full"; Example="Show-DataSources-full ss-core"},
    [pscustomobject]@{Name="Show-Data"; Overview="Show-Data"; Example="Show-Data 'ss-core' 'NTT_SNMP_Status'"},
    [pscustomobject]@{Name="Show-SDT"; Overview="Show-SDT"; Example="Show-SDT 'CHED'"},
    [pscustomobject]@{Name="Show-Netflow"; Overview="Show-Netflow"; Example="Show-Netflow 'CHED'"},
    [pscustomobject]@{Name="Show-Dead_On_Collector"; Overview="Show Dead devices On a Collector"; Example="Show-Dead_On_Collector '333'"},
    [pscustomobject]@{Name="Show-DisabledAlertsOnCollector"; Overview="Show Disabled Alerts On Resources on a Collector"; Example="Show-DisabledAlertsOnCollector '333'"},
    [pscustomobject]@{Name="Show-MissingSSID"; Overview="Show CI wil Missing SSID"; Example="Show-MissingSSID -id 'YourGroupID'"},
    [pscustomobject]@{Name="Show-MissingCompany"; Overview="Show CI wil Missing ntt.company"; Example="Show-MissingCompany -id 'YourGroupID'"},
    [pscustomobject]@{Name="Show_Stale_Devices"; Overview="Show Stale Devices as a filter on lastDataTime"; Example="Show_Stale_Devices -days '30'"},
    [pscustomobject]@{Name="Show_LMServices"; Overview="Show Service Devices"; Example="Show_LMServices"},
    [pscustomobject]@{Name="Show_LMServices_2_csv"; Overview="Show Service Devices and dump to a csv in current dir."; Example="Show_LMServices_2_csv"},
    [pscustomobject]@{Name="Show_LMServicesGroups"; Overview="Show Service group folders"; Example="Show_LMServicesGroups"},
    [pscustomobject]@{Name="Find-Report"; Overview="Find a report"; Example="Find-Report --LastModifyUserName 'ryan'"},
    [pscustomobject]@{Name="Find-Service"; Overview="Find a service with a name"; Example="Find-Service -searchTerm 'yourSearchTerm'"},
    [pscustomobject]@{Name="Show-ClassRouterInTree"; Overview="Show Class Router In Tree output."; Example="Show-ClassRouterInTree -ParentId '12399' -OutputCsvPath 'output.csv'"},
    [pscustomobject]@{Name="Show-GroupDeviceCounts"; Overview="Show Resources Instance Counts for a group."; Example="Show-GroupDeviceCounts -GroupId '1234' -OutputFileName 'output.csv'"},
    [pscustomobject]@{Name="Show-DeviceData"; Overview="Show Device DataSource and Instance Count."; Example="Show-DeviceData -displayName '1234'"},
    [pscustomobject]@{Name="Show-DeviceData_group"; Overview="Show Device DataSource and Instance Count for a group."; Example="Show-DeviceData_group -groupId 2122 -csvFileName 'DeviceData.csv'"},
    [pscustomobject]@{Name="Show-ERI"; Overview="Show the ERI on a device."; Example="Show-ERI -DisplayName 'nw-backup'"},
    [pscustomobject]@{Name="Set-ERI"; Overview="Set the ERI on a device."; Example="Set-ERI -DisplayName 'MyDevice01' -INERI 'abc-123-xyz'"},
    [pscustomobject]@{Name="Export-LMDeviceAudit"; Overview="Inventory report"; Example="Export-LMDeviceAudit -FullPath 'ESV/All' -OutputPath 'C:\Reports\ESV_Audit.csv'"},
    [pscustomobject]@{Name="Show-AP_Instances_on_WLC"; Overview="Cisco AP Inventory report for WOW etc"; Example="Show-AP_Instances_on_WLC'"},
    [pscustomobject]@{Name="Get-LmAlertbytype"; Overview="Show alerts filtering by instance name"; Example="Get-LmAlertbytype -DaysBack 2 -InstanceFilter 'Juniper_Mist_AP_Health'"},
	
    [pscustomobject]@{Name="Export-CPUInstanceCounts"; Overview="Show Device DataSource and Instance Count for a group filtered on CPU|PRocessor."; Example="Export-CPUInstanceCounts -GroupId 9766 -OutputFile 'CPU_InstanceCounts.csv'"},
    [pscustomobject]@{Name="Show-ABCG"; Overview="Show ABCG."; Example="Show-ABCG or Show-ABCG -filter 'KPMG'"},
    [pscustomobject]@{Name="Update-ABCG"; Overview="Update devices to use ABCG."; Example="Update-ABCG -CollectorGroupName 'KPMG Collector Group' -TargetCollectorGroupId '52'"},
    [pscustomobject]@{Name="Show_device_by_siteid -siteId '5740'"; Overview="Search for devices with siteid."; Example="Show_device_by_siteid -siteId '5740'"},
    [pscustomobject]@{Name="Export-DeviceGroupAudit"; Overview="Export Resource, DataSources and the Instance counts."; Example="Export-DeviceGroupAudit -GroupId 4791 -OutputPath 'C:\Reports\GroupAudit.csv'"},
    [pscustomobject]@{Name="Export-LMAlertSettingsBulk"; Overview="Export alerts applied at a group for DataSources."; Example="Get-Help Export-LMAlertSettingsBulk -Examples"},
    
    [PSCustomObject]@{Name = "__"; Overview = "__";Example="__" }, # Blank line
    [pscustomobject]@{Name="Get-CurrentDate"; Overview="Get the current date"; Example="Get-CurrentDate"},
    [pscustomobject]@{Name="Get-GroupDetails"; Overview="Get-GroupDetails -Parentid 4615"; Example="Get-GroupDetails -Parentid '4615'"},
    [pscustomobject]@{Name="Get-GroupDetails_to_csv "; Overview="Get-GroupDetails_to_csv"; Example="Get-GroupDetails -Parentid '4615'"},
    [pscustomobject]@{Name="Get-GroupDetails_with_devicecount"; Overview="Get-GroupDetails_with_devicecoun"; Example="Get-GroupDetails_with_devicecount -Parentid '12787'"},
    [pscustomobject]@{Name="Get-SwaggerDetails"; Overview="Get-SwaggerDetails off LM portal"; Example="Get-SwaggerDetails"},
    [PSCustomObject]@{Name = "__"; Overview = "__";Example="__" }, # Blank line    

    [pscustomobject]@{Name="Set-DeviceMonitoringState_device"; Overview="Change NTT.Monitoring.State to Active"; Example="Set-DeviceMonitoringState_device -displayname 'ss-core'"},
    [pscustomobject]@{Name="Set-DeviceMonitoringState_group"; Overview="Change NTT.Monitoring.State to Active"; Example="Set-DeviceMonitoringState_device -groupid 'id'"},
    [pscustomobject]@{Name="Start-Autodiscovery"; Overview="Start-Autodiscovery of devices in a group"; Example="Start-Autodiscovery 'id'"},
    [pscustomobject]@{Name="Get-PortalInfo"; Overview="Get-PortalInfo"; Example="Get-PortalInfo"},
    
    [PSCustomObject]@{Name = "__"; Overview = "__";Example="__" }, # Blank line    
    [pscustomobject]@{Name="Generate-RandomPassword"; Overview="Generate Random Password"; Example="Generate-RandomPassword"},
    [pscustomobject]@{Name="Create_LMUser"; Overview="Create a LM local user on the connected portal"; Example="Create_LMUser -Username <username> -First <first> -Last <last> -Email <email> -RoleName <rolename>"}
)
# Used to show the menu.
#Show-Menu -data $menu
#Show-Menu -data $menu -filter "Collector"
Show-Menu -data $menu -filter . # show all
Write-Host "You can filter this menu via: Show-Menu -data `$menu -filter ." -ForegroundColor Yellow
Write-Host "Or using quoted key words: Show-Menu -data `$menu -filter `'Collector'" -ForegroundColor Yellow

# EOF
