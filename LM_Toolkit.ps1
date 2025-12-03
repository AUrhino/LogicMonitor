<#
.SYNOPSIS
    A Collection of LogicMonitor tools and snipets to assist with using the product

.DESCRIPTION
    A collection of tools to assist with using the product. 

.EXAMPLE
    Load via:
    . LM_Toolkit.ps1

.EXAMPLE
    Show-Menu -data $menu -filter .

.EXAMPLE
    Show-Menu -data $menu -filter "Show" # To limit the menu to words with Show or show.

.NOTES
    Created by Ryan Gillan Oct 2025.
.NOTES
    Requires "Logic.Monitor" PowerShell module and appropriate API credentials.
.NOTES
    Requires PowerShell 7 (pwsh) to run.
.NOTES
    Requires the folowing module: https://pwshspectreconsole.com/guides/install/

.LINK
    https://github.com/AUrhino/LogicMonitor/blob/main/LM_Toolkit.ps1

#>

# Check if Spectre.Console module is imported
if (-not (Get-Module -ListAvailable -Name PwshSpectreConsole)) {
    try {
        Write-Host "PwshSpectreConsole module not found. Attempting to install..."
        Install-Module -Name PwshSpectreConsole -Scope CurrentUser -Force
    } catch {
        Write-Error "Failed to install PwshSpectreConsole module. Please install it manually.`nInstallation method:`nInstall-Module -Name PwshSpectreConsole -Scope CurrentUser -Force"
        exit
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-Resources {
<#
.SYNOPSIS
    Show Resources in LogicMonitor

.DESCRIPTION
    Retrieves and displays resources (devices) from a specified LogicMonitor device group.

.PARAMETER GroupId
    The ID of the LogicMonitor device group to query.

.EXAMPLE
    Show-Resources -GroupId '123'
     * Where '123' is the group ID of the LogicMonitor device group.
#>

    param (
        [Parameter(Mandatory = $false)]
        [string]$GroupId
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        Write-Warning "GroupId is required."
        Get-Help Show-Resources -Examples
        return
    }

    try {
        $devices = Get-LMDeviceGroupDevices -Id $GroupId -IncludeSubGroups $true
        if ($devices) {
            $devices
        } else {
            Write-Warning "No devices found in group ID '$GroupId'."
        }
    } catch {
        Write-Error "Failed to retrieve devices for group ID '$GroupId'.`n$_"
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-Dead_On_Collector {
<#
.SYNOPSIS
    Show dead devices assigned to a specific LogicMonitor Collector.

.DESCRIPTION
    Retrieves the number of hosts and lists devices with a "dead" status for a given Collector ID.

.PARAMETER CollectorId
    The ID of the LogicMonitor Collector to inspect.

.EXAMPLE
    Show-Dead_On_Collector -CollectorId 333
    Displays dead devices and host count for Collector ID 333.
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$CollectorId
    )

    if ([string]::IsNullOrWhiteSpace($CollectorId)) {
        Write-Warning "CollectorId is required."
        Get-Help Show-Dead_On_Collector -Example
        return
    }

    try {
        $collector = Get-LMCollector -Id $CollectorId
        $hosts = $collector.numberOfHosts

        $deadDevices = Get-LMDevice -Filter "currentCollectorId -eq $CollectorId" |
            Where-Object { $_.hostStatus -eq "dead" } |
            Select-Object displayName, hostStatus |
            Sort-Object displayName

        Write-Host "`nCollector ID: $CollectorId" -ForegroundColor Cyan
        Write-Host "Number of Hosts: $hosts" -ForegroundColor Cyan
        Write-Host "Dead Devices:" -ForegroundColor Red

        if ($deadDevices) {
            $deadDevices | Format-Table -AutoSize
        } else {
            Write-Host "No dead devices found." -ForegroundColor Green
        }
    } catch {
        Write-Error "Error retrieving data for collector ID '$CollectorId'.`n$_"
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-Collectors {
<#
.SYNOPSIS
    Show LogicMonitor Collectors.

.DESCRIPTION
    Show LogicMonitor Collectors.

.EXAMPLE
    Show-Collectors
    Displays Collectors
#>
    $LM_Collectors = Get-LMCollector |
        Select-Object Id, Hostname, Description, Build, CollectorSize, Platform, CollectorGroupName, NumberOfInstances, NumberOfHosts, IsDown |
        Sort-Object CollectorGroupName
    $LM_Collectors | ft
}

<# ---------------------------------------------------------------------------- #>
function Show-DeadCollectors {
<#
.SYNOPSIS
    Show LogicMonitor Collectors with DEAD status

.DESCRIPTION
    Show LogicMonitor Collectors.

.EXAMPLE
    Show-DeadCollectors
    Displays Collectors marked as dead
#>
    $LM_Collectors = Get-LMCollector | Select-Object id,hostname,collectorGroupName,isDown | Where-Object { $_.isDown -eq $true }
    if ($LM_Collectors) {
        $LM_Collectors | ForEach-Object { Write-Host "Down Collectors: `n ID: $($_.id), Name: $($_.hostname), Group: $($_.collectorGroupName)" -ForegroundColor Red }
    } else {
        Write-Host "All Collectors are up." -ForegroundColor Green
    }
}
<# ---------------------------------------------------------------------------- #>
function Show-ABCG {
<#
.SYNOPSIS
    Show LogicMonitor Collectors and Auto Balanced Collector Groups (ABCG)

.DESCRIPTION
    Show LogicMonitor Collectors and Auto Balanced Collector Groups (ABCG)

.EXAMPLE
    Show-ABCG
.EXAMPLE
     Show-ABCG -filter Something
#>
    param (
        [string]$filter
    )
    Get-LMCollectorGroup -Filter "autoBalance -eq 'True'" | Where-Object { $_.Name -match $filter } | Select-Object ID, Name, Description
}
<# ---------------------------------------------------------------------------- #>
function Set-LMDevicesToABCG {
<#
.SYNOPSIS
    Show LogicMonitor Collectors and Auto Balanced Collector Groups (ABCG)

.DESCRIPTION
    This function checks devices assigned to collectors within a specified Auto Balanced Collector Group (ABCG).
    It compares each device's autoBalancedCollectorGroupId with the target ABCG ID and optionally reports or fixes mismatches.
    Devices listed in the 'host' custom property of the collector group will be excluded from processing.

.EXAMPLE
    Report only:
    Set-LMDevicesToABCG -CollectorGroupName "ABCG Name" -Report $true -Fix $false

.EXAMPLE
    Report and Fix:
    Set-LMDevicesToABCG -CollectorGroupName "ABCG Name" -Report $true -Fix $true
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$CollectorGroupName,

        [bool]$Report = $true,
        [bool]$Fix = $false
    )
	#clear varibles
    $ABCG = ""
    $ABCGid  = ""
	$LMCollector =""

    # Get the collector group object
    $ABCG = Get-LMCollector -Filter "collectorGroupName -eq '$CollectorGroupName'"
    $ABCGid = $ABCG.collectorGroupId | Select-Object -First 1

    # Extract custom properties
    $customProperties = $ABCG | Select-Object -ExpandProperty CustomProperties
    # Check if 'host' property exists
    $hostProperty = $customProperties | Where-Object { $_.Name -eq 'host' }

    if (-not $hostProperty) {
        Write-Error "ERROR: The custom property 'host' was not found in Collector group '$CollectorGroupName'."
        return
    }

    # Get host values
    $ABCG_Hosts = $hostProperty.Value
    Write-Host "Boxes to filter out: $ABCG_Hosts"

    # Convert host list to array
    $excludedHosts = $ABCG_Hosts -split '\s+'

    # Loop through each collector ID
    foreach ($LMCollector in $ABCG.id) {
        $devices = Get-LMDevice -Filter "currentCollectorId -eq $LMCollector" | Where-Object { $_.displayName -notin $excludedHosts }

        $totalDevices = $devices.Count
        $counter = 1

        foreach ($device in $devices) {
            Write-Host "Checking: $counter of $($totalDevices): $($device.displayName)" -ForegroundColor Yellow
            $deviceDetails = Get-LMDevice -DisplayName $device.displayName | Select-Object displayName, autoBalancedCollectorGroupId

            if ($deviceDetails.autoBalancedCollectorGroupId -ne $ABCGid) {
                if ($Report) {
                    Write-Output "Mismatch found: $($deviceDetails.displayName)"
                }

                if ($Fix) {
                    Write-Output "Fixing: $($deviceDetails.displayName)"
                    Get-LMDevice -displayname $deviceDetails.displayname | Set-LMDevice -AutoBalancedCollectorGroupId $ABCGid > $null
                }
            }

            $counter++
        }
    }

    Write-Host "Completed processing for Collector Group '$CollectorGroupName'."  -ForegroundColor Green
}

# Example usage:
# Set-LMDevicesToABCG -CollectorGroupName "DC Fyshwick" -Report $true -Fix $false
<# ---------------------------------------------------------------------------- #>
function Set-New_Collector {
<#
.SYNOPSIS
    Will change the Collectors on Resources in a group

.DESCRIPTION
    Will get a list of Resources in a group and change the Collectors in bulk.

.EXAMPLE
    Set-New_Collector -groupid 6194 -PreferredCollectorId 484
#>
    param (
        [int]$groupid,
        [int]$PreferredCollectorId
    )

    if (-not $groupid -or -not $PreferredCollectorId) {
        Write-Host "Example usage: Set-New_Collector -groupid 6194 -PreferredCollectorId 484" -ForegroundColor Yellow
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $groupid
    foreach ($item in $devices.id) {
        Write-Host "Updating device ID: $item"
        Get-LMDevice -Id $item | Set-LMDevice -PreferredCollectorId $PreferredCollectorId > $null
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-Resoures_in_SDT {
<#
.SYNOPSIS
    Show LogicMonitor Resources in an SDT

.DESCRIPTION
    Show LogicMonitor Resources in an SDT

.EXAMPLE
    Show-Resoures_in_SDT
#>
	Get-LMDevice -Filter "sdtStatus -contains 'SDT'"  | select displayname,name,hoststatus,sdtStatus | sort displayname
}

<# ---------------------------------------------------------------------------- #>
function Show-Users {
<#
.SYNOPSIS
    Show LogicMonitor users

.DESCRIPTION
    Show LogicMonitor users

.EXAMPLE
    Show-Users
#>
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

<# ---------------------------------------------------------------------------- #>
function Show-Roles {
<#
.SYNOPSIS
    Show LogicMonitor roles

.DESCRIPTION
    Show LogicMonitor roles

.EXAMPLE
    Show-roles
#>
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
<# ---------------------------------------------------------------------------- #>
function Show-UserGroups {
<#
.SYNOPSIS
    Show LogicMonitor user groups

.DESCRIPTION
    Show LogicMonitor roles

.EXAMPLE
    Show-UserGroups
#>
    $roles = Get-LMUserGroup | Select-Object id, name, description
    $table = @()

    foreach ($role in $roles) {
        $table += [pscustomobject]@{
            ID          = $role.id
            Name        = $role.name
            Description = $role.description
        }
    }

    Format-SpectreTable -Title "UserGroups" -Data $table
}

<# ---------------------------------------------------------------------------- #>
<#
.SYNOPSIS
    Creates a LogicMonitor user with a randomly generated secure password.

.DESCRIPTION
    This script defines two functions:
    - Generate-RandomPassword: Generates a secure password with a mix of character types.
    - Create_LMUser: Creates a LogicMonitor user with specified details and assigns roles and groups.
      It checks for existing users before creation and formats input values.

.EXAMPLE
    Create_LMUser -Username "michael.ceola@global.ntt" `
                  -FirstName "Michael" `
                  -LastName "Ceola" `
                  -Email "michael.ceola@global.ntt" `
                  -RoleName "administrator" `
                  -GroupName "NTT DATA View Operator" `
                  -Mobile "0411123123" `
                  -Ticket "SVR12345"
#>

function Generate-RandomPassword {
    $length = 12
    $upper = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower = [char[]]'abcdefghijklmnopqrstuvwxyz'
    $digits = [char[]]'0123456789'
    $special = [char[]]'~!$%^()_-+=\{}[]@#&\|;:,.<>.?/'

    # Ensure at least one of each required character type
    $passwordChars = @(
        Get-Random -InputObject $upper
        Get-Random -InputObject $lower
        Get-Random -InputObject $digits
        Get-Random -InputObject $special
    )

    # Fill the rest of the password with random characters from all sets
    $allChars = $upper + $lower + $digits + $special
    $remainingLength = $length - $passwordChars.Count
    for ($i = 0; $i -lt $remainingLength; $i++) {
        $passwordChars += Get-Random -InputObject $allChars
    }

    # Shuffle the characters to avoid predictable patterns
    $shuffledPassword = ($passwordChars | Sort-Object {Get-Random}) -join ''
    return $shuffledPassword
}

function Capitalize-FirstLetter {
    param ([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    return ($Text.Substring(0,1).ToUpper() + $Text.Substring(1).ToLower())
}

function Create_LMUser {
    param (
        [string]$Username,
        [string]$FirstName,
        [string]$LastName,
        [string]$Email,
        [string]$RoleName,
        [string]$GroupName,
        [string]$Mobile,
        [string]$Ticket
    )

    if (-not $PSBoundParameters['Username']) {
        Write-Host "Example usage: Create_LMUser -Username <username> -FirstName <firstname> -LastName <lastname> -Email <email> -RoleName <rolename> -GroupName <groupname> -Mobile <mobile> -Ticket <ticket>"
        return
    }

    # Format inputs
    $Username  = $Username.ToLower()
    $Email     = $Email.ToLower()
    $FirstName = Capitalize-FirstLetter $FirstName
    $LastName  = Capitalize-FirstLetter $LastName

    # Check if user already exists
    $existingUser = Get-LMUser | Select-String -Pattern $Username
    if ($existingUser) {
        Write-Host "User '$Username' already exists. Skipping creation." -ForegroundColor Red
        return
    }

    $Password = Generate-RandomPassword

    # Create new user with roles
    New-LMUser -Username $Username `
               -Password $Password `
               -FirstName $FirstName `
               -LastName $LastName `
               -Email $Email `
               -Phone $Mobile `
               -Note $Ticket `
               -RoleNames @($RoleName) `
               -UserGroups @($GroupName) `
               -ForcePasswordChange $true `
               -Status "active" `
               -Timezone "Australia/Sydney"

    # Print summary table
    $table = @(
        [pscustomobject]@{Name="Username"; Value=$Username},
        [pscustomobject]@{Name="First Name"; Value=$FirstName},
        [pscustomobject]@{Name="Last Name"; Value=$LastName},
        [pscustomobject]@{Name="Email"; Value=$Email},
        [pscustomobject]@{Name="Role Name"; Value=$RoleName},
        [pscustomobject]@{Name="Group Name"; Value=$GroupName},
        [pscustomobject]@{Name="Mobile"; Value=$Mobile},
        [pscustomobject]@{Name="Ticket"; Value=$Ticket},
        [pscustomobject]@{Name="Password"; Value=$Password}
    )

    Format-SpectreTable -Title "Creation Summary" -Data $table
}

<# ---------------------------------------------------------------------------- #>
function Show-Netflow {
<#
.SYNOPSIS
    Show LogicMonitor Resources with netflow enabled

.DESCRIPTION
    Show LogicMonitor Resources with netflow enabled

.EXAMPLE
    Show-Netflow
#>
    $netflowfilter = 'systemProperties -eq "{\"name\":\"system.enablenetflow\",\"value\":\"true\"}"'
    Get-LMDevice -Filter $netflowfilter
}

<# ---------------------------------------------------------------------------- #>
function Show-LMServices {
<#
.SYNOPSIS
    Show LogicMonitor Services

.DESCRIPTION
    Show LogicMonitor Services

.EXAMPLE
    Show_LMServicesGroups
#>
    $LMServices = Get-LMService
    $results = @()
    foreach ($item in $LMServices) {
        $results += [PSCustomObject]@{
            Id     = $item.Id
            Name   = $item.Name
            fullPath  = $item.$fullPath
            appliesTo  = $item.$appliesTo
            }
        }
    Format-SpectreTable -Title "LM Services" -Data $results
}
<# ---------------------------------------------------------------------------- #>
function Find-Service {
<#
.SYNOPSIS
    Find LogicMonitor services.

.DESCRIPTION
    Searches for devices with the collector description "Service Data Aggregator" and filters by name.

.EXAMPLE
    Find-Service -searchTerm "API"
#>

    param (
        [string]$searchTerm
    )

    $services = Get-LMDevice -Filter 'collectorDescription -eq "Service Data Aggregator"' |
        Where-Object { $_.name -like "*$searchTerm*" }

    $services | Format-SpectreTable
}

<# ---------------------------------------------------------------------------- #>
function Show-ERI {
<#
.SYNOPSIS
    Find LogicMonitor ERI on a Resouce.

.DESCRIPTION
    Find LogicMonitor Resouce and show the ERI

.EXAMPLE
    Show-ERI -DisplayName 'nw-backup'
#>
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

<# ---------------------------------------------------------------------------- #>
function Get-VSphereGuests {
    <#
    .SYNOPSIS
        Show guest VMs on a vSphere device.

    .DESCRIPTION
        Captures guest VM details from a vSphere device in LogicMonitor and exports them to CSV in the current path.

    .PARAMETER DeviceName
        The display name of the vSphere device in LogicMonitor.

    .EXAMPLE
        Run:
        Get-VSphereGuests -DeviceName "cbf-vmw-vc-n-01"
    .EXAMPLE
        Help:
        get-help Get-VSphereGuests -full

    .NOTES
        Version 1.2
        Written by Ryan Gillan
    #>

    param (
        [string]$DeviceName
    )

    #Requires -Version 7.0
    #Requires -Modules Logic.Monitor

    if (-not $DeviceName) {
        Write-Host "`n[!] Please provide a device name." -ForegroundColor Red
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host "    Get-VSphereGuests -DeviceName 'cbf-vmw-vc-n-01'" -ForegroundColor Yellow
        return
    }

    $Devices = Get-LMDevice -DisplayName $DeviceName

    if (-not $Devices) {
        Write-Host "Device '$DeviceName' not found in LogicMonitor" -ForegroundColor Red
        return
    }

    $Results = @()

    foreach ($Device in $Devices) {
        $DataSource = Get-LMDeviceDatasourceList -id $Device.id | Where-Object { $_.dataSourceName -eq "VMware_vSphere_VirtualMachineStatus" }
        if ($DataSource) {
            $Instances = Get-LMDeviceDatasourceInstance -DatasourceId $DataSource.datasourceId -DeviceId $Device.id
            foreach ($i in $Instances) {
                $AutoProps = @{}

                try {
                    $AutoProps = $i | Select-Object -ExpandProperty autoProperties
                } catch {
                    $AutoProps = @{}
                }

                $obj = [ordered]@{
                    DeviceName      = $Device.displayName
                    Name            = $i.Name
                    groupName       = $i.groupName
                    description     = $i.description
                    wildValue       = $i.wildValue
                    sdtStatus       = $i.sdtStatus
                    disableAlerting = $i.disableAlerting
                    stopMonitoring  = $i.stopMonitoring
                    Id              = $i.id
                }

                if ($AutoProps) {
                    foreach ($prop in $AutoProps) {
                        if ($prop.name -and $prop.value) {
                            $obj[$prop.name] = $prop.value
                        }
                    }
                }

                $Results += New-Object PSObject -Property $obj
            }
        }
    }

    $timestamp = Get-Date -Format "ddMMyyyy"
    $filename = "$DeviceName_Vsphere_guests_$timestamp.csv"
    $Results | Export-Csv -NoTypeInformation -Path $filename

    Write-Host "Export complete: $filename" -ForegroundColor Green
}
# Run via:
# Get-VSphereGuests -DeviceName "cbf-vmw-vc-n-01"

# EOF
<# ---------------------------------------------------------------------------- #>
function Find-Report {
<#
.SYNOPSIS
    Find LogicMonitor ERI on a Resouce.

.DESCRIPTION
    Find LogicMonitor Resouce and show the ERI

.EXAMPLE
    Find-Report -Type '"<Alert|SLA|trends|threshold|inventory|metric|CPU|Interface|Website|Netflow>"'
.EXAMPLE
    Find-Report -Type 'Alert' -Name 'CPU' -output 'CSV'
.EXAMPLE
    Find-Report --LastModifyUserName 'ryan'
.EXAMPLE
    Find-Report -Name 'CPU|whatever'
.EXAMPLE
    Find-Report -output 'CSV|HTML|PDF
#>
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
		Get-Help Find-Report -Example
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

<# ---------------------------------------------------------------------------- #>
function Set-Properties {
<#
.SYNOPSIS
    Adds properties to each device in a LogicMonitor group.

.DESCRIPTION
    This function retrieves all devices in the specified group and adds the provided properties to each device.

.EXAMPLE
    Set-Properties -groupID 123 -Properties @{"wmi.user"="TEST";"wmi.pass"="TEST"}

.EXAMPLE
    Set-Properties -groupID 123 -Properties @{"snmp.community"="public";}

.EXAMPLE
    Set-Properties -groupID 123 -Properties @{'snmp.priv'='snmppriv';'snmp.privToken'='snmpprivToken';'snmp.auth'='snmpauth';'snmp.authToken'='snmpauthToken';}

.EXAMPLE
    Set-Properties -groupID 123 -Properties @{'ntt.company'='DEMO';}
	
.EXAMPLE
    Set-Properties -groupID 123 -Properties @{'location'='123 Smith St, NSW, Australia';}
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$groupID,

        [Parameter(Mandatory = $false)]
        [hashtable]$Properties
    )

    if (-not $PSBoundParameters.ContainsKey('groupID') -or -not $PSBoundParameters.ContainsKey('Properties')) {
        Write-Warning "The groupID and Properties are required."
        Get-Help Set-Properties -Examples
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $groupID
	Write-Host "Found: $($devices.count) devices"

    foreach ($device in $devices) {
        $deviceDetails = Get-LMDevice -displayName $device.displayName
        if ($deviceDetails) {
			Write-Host "Updating device: $($device.displayName)"
            Set-LMDevice -Id $deviceDetails.Id -Properties $Properties -PropertiesMethod Replace | Out-Null
        } else {
            Write-Warning "Device '$($device.displayName)' not found or could not be retrieved."
        }
    }
}

<# ---------------------------------------------------------------------------- #>
function Remove-Properties {
<#
.SYNOPSIS
    Removes one or more properties from each device in a LogicMonitor group.

.DESCRIPTION
    This function retrieves all devices in the specified group and removes the specified properties from each device.

.EXAMPLE
    Remove-Properties -groupID 123 -PropertyNames @("wmi.user")

.EXAMPLE
    Remove-Properties -groupID 123 -PropertyNames @("wmi.user", "wmi.pass")
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$groupID,

        [Parameter(Mandatory = $false)]
        [string[]]$PropertyNames
    )

    if (-not $PSBoundParameters.ContainsKey('groupID') -or -not $PSBoundParameters.ContainsKey('PropertyNames')) {
        Write-Warning "The groupID and PropertyNames parameters are required."
        Get-Help Remove-Properties -Examples
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $groupID

    foreach ($device in $devices) {
        $deviceDetails = Get-LMDevice -displayName $device.displayName
        if ($deviceDetails) {
            foreach ($property in $PropertyNames) {
                Remove-LMDeviceProperty -Id $deviceDetails.Id -Propertyname $property -Confirm:$false
            }
        } else {
            Write-Warning "Device '$($device.displayName)' not found or could not be retrieved."
        }
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-DeviceData {
<#
.SYNOPSIS
    Shows the count of Datasource and Instances for a devices

.DESCRIPTION
    Shows the count of Datasource and Instances for a devices

.PARAMETER groupId
    The ID of the device group to query.

.PARAMETER csvFileName
    The name of the CSV file to write the results to.

.INPUTS
    groupId - The ID of the device group.
    csvFileName - The name of the CSV file.

.EXAMPLE
    Show-DeviceData -displayName SAMPLE
#>
    param (
        [string]$displayName
    )

    if (-not $displayName) {
        Write-Host "Please provide a display name. Example usage: Show-DeviceData -displayName SAMPLE" -ForegroundColor Yellow
		Get-Help Show-DeviceData -examples
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
<# ---------------------------------------------------------------------------- #>
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
#>
    param (
        [int]$groupId,
        [string]$csvFileName = "DeviceData.csv"
    )

    if (-not $groupId) {
        Write-Host "Please provide a group ID. Example usage: Show-DeviceData_group -groupId 2122 -csvFileName 'DeviceData.csv'" -ForegroundColor Yellow
        Get-Help Show-DeviceData_group -examples
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

<# ---------------------------------------------------------------------------- #>
function Show-BackupConfig {
<#
.SYNOPSIS
    Shows the backup datasources in place

.DESCRIPTION
    Shows the backup datasources in place

.PARAMETER displayname
    The displayname of the device group to query.

.EXAMPLE
    Show-BackupConfig -displayname 'displayname'
#>
    param (
        [string]$displayname
    )
    if (-not $displayname['']) {
        Write-Host "Example usage: Show-BackupConfig -displayname 'displayname'" -ForegroundColor Yellow
        Get-Help Show-BackupConfig -examples
        return
    }
    $devices = Get-LMDevice -displayname $displayname
    Export-LMDeviceConfigBackup -deviceid $Ci.id
}

<# ---------------------------------------------------------------------------- #>
function Show-DeviceOnCollector {
<#
.SYNOPSIS
    Query a Collector for a list of Resources

.DESCRIPTION
    Query a Collector for a list of Resources

.PARAMETER collector
    The Collector to query.

.EXAMPLE
    Show-DeviceOnCollector
#>
    param (
    [int]$collector
    )

    if (-not $collector) {
        Write-Host "Usage: Show-DeviceOnCollector -collector <collectorId>" -ForegroundColor Yellow
        return
    }

        Get-LMDevice -Filter "currentCollectorId -eq $collector" | Select-Object displayname, name, hostStatus | sort-Object displayname, hostStatus | Format-SpectreTable -title "Devices on Collector: $collector"
}

<# ---------------------------------------------------------------------------- #>
function Show-Devices_in_group {
<#
.SYNOPSIS
    Query a LogicMonitor device group for a list of resources.

.DESCRIPTION
    Retrieves all devices from the specified LogicMonitor device group, including subgroups.

.PARAMETER groupID
    The ID of the device group to query.

.EXAMPLE
    Show-Devices_in_group -groupID 123
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$groupID
    )

    if (-not $PSBoundParameters.ContainsKey('groupID')) {
        Write-Warning "The groupID parameter is required."
        Get-Help Show-Devices_in_group -Examples
        return
    }

    $devices = Get-LMDeviceGroupDevices -Id $groupID -IncludeSubGroups $true
    $devices
}
<# ---------------------------------------------------------------------------- #>
function Show-Data {
<#
.SYNOPSIS
    Query a LogicMonitor device for datasource instance data.

.DESCRIPTION
    Retrieves instance data for a specified datasource on a given device.

.EXAMPLE
    Show-Data <displayname> <datasource_name>
    Show-Data ss-core network_interfaces
#>

    [String]$displayName = $args[0] # Device display name
    [String]$dataSourceName = $args[1] # Datasource name

    if (-not $displayName -or -not $dataSourceName) {
        Write-Warning "Missing parameters. Example usage:"
        Get-Help Show-Data -Examples
        return
    }

    $device = Get-LMDevice -DisplayName $displayName

    if ($device) {
        $instances = Get-LMDeviceInstanceList -Filter "name -contains '$dataSourceName'" -Name $device.name |
            Select-Object name, deviceDisplayName, id

        if ($instances) {
            Get-LMDeviceInstanceData -StartDate (Get-Date).AddHours(-7) -EndDate (Get-Date) -Ids $instances.id -AggregationType "last" -Period 1 |
                Select-Object dataSourceName, dataPoints, values
        } else {
            Write-Warning "No instances found for datasource '$dataSourceName' on device '$displayName'."
        }
    } else {
        Write-Warning "Device '$displayName' not found."
    }
}

<# ---------------------------------------------------------------------------- #>
function Show-DisabledAlertsOnCollector {
<#
.SYNOPSIS
    Displays devices with alerting disabled on a specified LogicMonitor collector.

.DESCRIPTION
    This function retrieves the collector by ID, counts the number of hosts assigned to it,
    and lists all devices that have alerting disabled and are currently assigned to that collector.

.PARAMETER CollectorId
    The ID of the LogicMonitor collector to query.

.EXAMPLE
    Show-DisabledAlertsOnCollector -CollectorId 33

    This example retrieves all devices assigned to collector ID 33 that have alerting disabled,
    and displays them in a formatted table along with collector details.
#>

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


<# ---------------------------------------------------------------------------- #>
<# ---------------------------------------------------------------------------- #>


<# ----------------------------= Menu =-------------------------------------- #>
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
    $data | Format-SpectreTable -Title "--= LM toolkit =--"
}


$menu = @(
# Menu section:
    [pscustomobject]@{Name="Show-Menu"; Overview="Show this menu"; Example="Show-Menu -data `$menu -filter '<.|Collector|devices>'"},
    [PSCustomObject]@{Name = "`n "; Overview = " ";Example=" " }, # Blank line 

# Show/Get section:
    [pscustomobject]@{Name="Show-Resources"; Overview="Show Resources and add a group ID"; Example="Show-Resources <ID>"},
    [pscustomobject]@{Name="Show-Dead_On_Collector"; Overview="Show Dead On a Collector"; Example="Show-Dead_On_Collector -CollectorId <333>  "},
    [pscustomobject]@{Name="Show-DeviceOnCollector "; Overview="Show Resources on a Collector"; Example="Show-DeviceOnCollector -CollectorId <333>  "},
    [pscustomobject]@{Name="Show-DisabledAlertsOnCollector"; Overview="Show Disabled Alerts On Resources on a Collector"; Example="Show-DisabledAlertsOnCollector '333'"},
    [pscustomobject]@{Name="Show-DeviceData"; Overview="Show Device DataSource and Instance Count."; Example="Show-DeviceData -displayName '1234'"},
    [pscustomobject]@{Name="Show-DeviceData_group"; Overview="Show Device DataSource and Instance Count for a group."; Example="Show-DeviceData_group -groupId 2122 -csvFileName 'DeviceData.csv'"},
    [pscustomobject]@{Name="Show-BackupConfig"; Overview="Show backup configs on a Resource"; Example="Show-BackupConfig -displayname 'displayname'"},
    [pscustomobject]@{Name="Show-Devices_in_group"; Overview="Show Devices in group"; Example="Show-Devices_in_group -groupID 123"},
    [pscustomobject]@{Name="Show-Data"; Overview="Show-Data"; Example="Show-Data 'ss-core' 'NTT_SNMP_Status'"},
    [pscustomobject]@{Name="Show-Resoures_in_SDT"; Overview="Show Resoures in an SDT"; Example="Show-Resoures_in_SDT"},
    [pscustomobject]@{Name="Show-Netflow"; Overview="Show Resoures with Netflow option enabled"; Example="Show-Netflow"},
    [pscustomobject]@{Name="Show-LMServices"; Overview="Show Services Resoures"; Example="Show-LMServices"},
    [pscustomobject]@{Name="Show-ERI"; Overview="Show the ERI details on an Resource"; Example="Show-ERI -DisplayName 'nw-backup'"},
    [pscustomobject]@{Name="Get-VSphereGuests"; Overview="Show the guest VM on vsphere"; Example="Get-VSphereGuests -DeviceName 'vcsa'"},

# Set/Change/Find section:
    [PSCustomObject]@{Name = "`n "; Overview = " ";Example=" " }, # Blank line
    [pscustomobject]@{Name="Set-Properties"; Overview="For devices in a group, adds properties eg set wmi or snmp creds."; Example="Set-Properties -groupID 123 -Properties @{'wmi.user'='TEST';'wmi.pass'='TEST'}"},
    [pscustomobject]@{Name="Remove-Properties"; Overview="For devices in a group, removes properties eg set wmi or snmp creds."; Example="Remove-Properties -groupID 123 -Properties @{'wmi.user';'wmi.pass'}"},
    [pscustomobject]@{Name="Find-Service"; Overview="Find LogicMonitor services"; Example="Find-Service -searchTerm 'API'"},
    [pscustomobject]@{Name="Find-Report"; Overview="Find a Report"; Example="Find-Report -Name 'CPU|whatever'"},

# Collector section:
    [PSCustomObject]@{Name = "`n "; Overview = " ";Example=" " }, # Blank line
    [pscustomobject]@{Name="Show-Collectors"; Overview="Show Collectors"; Example="Show-Collectors"},
    [pscustomobject]@{Name="Show-DeadCollectors"; Overview="Show DeadCollectors"; Example="Show-DeadCollectors"},
    [pscustomobject]@{Name="Show-ABCG"; Overview="Show ABCG"; Example="Show-ABCG or Show-ABCG -filter 'KPMG'"},
	[pscustomobject]@{Name="Set-LMDevicesToABCG"; Overview="Report and/or fix ABCG."; Example="Set-ABCG_on_Resources -CollectorGroupName 'DC Fyshwick' -Report $true -Fix $false"},
	[pscustomobject]@{Name="Set-New_Collector"; Overview="Change the Collectors for devices in a group"; Example="Set-New_Collector -CollectorGroupName -groupid 123 -PreferredCollectorId 456"},


# User/role/group section:
    [PSCustomObject]@{Name = "`n "; Overview = " ";Example=" " }, # Blank line	
    [pscustomobject]@{Name="Show-Users"; Overview="Show-Users"; Example="Show-Users"},
    [pscustomobject]@{Name="Show-Roles"; Overview="Show-Roles"; Example="Show-Roles"},
    [pscustomobject]@{Name="Show-UserGroups"; Overview="Show-UserGroups"; Example="Show-UserGroups"},

# Last line of the menu
    [PSCustomObject]@{Name = "`n "; Overview = " ";Example=" " }, # Blank line
    [PSCustomObject]@{Name = "Help"; Overview = "Help";Example="Get-Help LM_Toolkit.ps1 -full" } #Note the "," should not exist.
)
# Used to show the menu.
Show-Menu -data $menu -filter . # show all
Write-Host "    You can filter this menu via: Show-Menu -data `$menu -filter ." -ForegroundColor Yellow
Write-Host "    Or using quoted key words: Show-Menu -data `$menu -filter `'Collector'" -ForegroundColor Yellow

<# ---------------------------------------------------------------------------- #>
# EOF