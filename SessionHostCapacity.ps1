<# 
    Purpose: 
        Increase and decrease capacity within a Session Host collection
    Author: 
        Victor Meyer (victor.meyer@salt.ky)
    Notes: 
        - 
    Version: 
        - 1.0 - 
#>

# // Variables

# RDS Variables
# This is one of the brokers in the farm
$Broker = "VM-AZS-RDS01.saltlab.online"
# The name of the virtual desktop collection
$CollectionName = "Virtual Desktop"
# Is HighlyAvailable Deployment
$HA = $false

# Session Limits
# The maximum number of sessions before a new host is added
$MaxSessions = 1
# The minimum number of sessions before host draining and power off occurs
$MinSession = 0
# Number of times to test for RDP connections after powering on a Session Host
$RetryAttempts = 30
# The minimum amount of hosts that should be online 
$MinHosts = 1
# Maintenance window for reducing session hosts
# Deprovisioning will only be attepted after this time
$StartTime = "13:00:00"
# Deprovisioning will not occur after this time
$EndTime = "05:00:00"

# Azure application / service principle name
# The Azure AD Application Id
$AppId = "f69df505-8d0a-4d28-b2c8-9d76253d9f8e"
# The Azure AD Tenant Id
$TenantId = "f798b6f5-00d8-4480-822a-4c8e5cd7d890"
# The Azure AD Application Certificate Thumbprint
$Thumbprint = "e3b5953fb64f3815fecaa5a502495c7986f3f990"
# Logging and tracking
# Script Log File Path
$LogFile = "C:\Maintenance\capacity.log"
# Script Database File | Note: This makes the script stateful!
$DatabaseFile = "C:\Maintenance\capacity.json"
# Store the environment type as either: Stack | Public
$Environment = "Stack"
# If Stack then setup management endpoint
$ManagementEndpoint = "https://management.local.azurestack.external"
# Virtual machine resource group
$VMResourceGroup = "lab-vdi"
# Subscription Id
$SubscriptionId = "a5bed567-3f86-4a59-ad80-d13963bb79d1"

## Functions

# Logging function
function Log
{
    <# 
        This function is used for logging.
        You can log to a file, event log or the console based on 3 types.
    #>  
    param([Parameter(Mandatory=$false)][string]$LogFile = $LogFile, 
          [Parameter(Mandatory=$false)][ValidateSet("Error","Warning","Information","Success")][string]$type = "Information",
          [Parameter(Mandatory=$true)][string]$msg,
          [Parameter(Mandatory=$false)][boolean]$writeTextLog = $true,
          [Parameter(Mandatory=$false)][boolean]$writeEventLog = $false,
          [Parameter(Mandatory=$false)][boolean]$writeHost = $true)
    end
    {
        # Make Log
        if((test-path -path $LogFile) -eq $false){
            $file = New-Item $LogFile -ItemType file 
        } 
        else {
            $file = Get-Item -Path $LogFile
        }
        # Log Rollover
        if($file.Length -ge 1mb){
            Remove-Item -Path ($file.FullName).Replace(".log",".lo_") -Force -ErrorAction SilentlyContinue
            Rename-Item -Path $file.FullName -NewName ($file.Name).Replace(".log",".lo_")
            $file = New-Item $lf -ItemType file
        }
        # EventLog 
        if($writeEventLog -eq $true){
            switch($type){
                "Error"  { Write-EventLog -LogName Application -Source Script -EntryType Error -EventID 3 -Message $msg; }
                "Warning"  { Write-EventLog -LogName Application -Source Script -EntryType Warning -EventID 2 -Message $msg; }
                "Information"  { Write-EventLog -LogName Application -Source Script -EntryType Information -EventID 1 -Message $msg; }
                "Success"  { Write-EventLog -LogName Application -Source Script -EntryType Information -EventID 4 -Message $msg; }
            }
        }
        # Console 
        if($writeHost -eq $true){
            switch($type){
                "Error"  { write-host -ForegroundColor Red -Object $msg }
                "Warning"  { write-host -ForegroundColor Yellow -Object $msg }
                "Information" { write-host -Object $msg}
                "Success" { write-host -ForegroundColor Green -Object $msg}
            }
        }
        # Append Log
        if($writeHost -eq $true){
        $msg = "$(Get-Date) - $type - $msg"
        $msg | Add-Content -Path $file.FullName
        }
    }
}
# New Server Object
function New-ServerObject
{
    param([string]$ServerName,[boolean]$Draining,[int]$TotalOnlineHours,[int]$MonthlyOnlineHours,[string]$LastModified)
    end
    {
        $Properties = @{
            ServerName = $ServerName
            Draining = $Draining
            TotalOnlineHours = $TotalOnlineHours
            MonthlyOnlineHours = $MonthlyOnlineHours
            LastModified = $LastModified
        }
        $Object = New-Object psobject -Property $Properties
        return $Object
    }
}
# Load Script Database File
function Get-Database
{
    param([string]$DatabaseFile)
    end
    {
        $Database = Test-Path -Path $DatabaseFile
        if(!$Database) {
            ConvertTo-Json @() | Out-File -FilePath $DatabaseFile
        } else {
            $Database = [System.Collections.Generic.List[System.Object]]
            $Database = Get-Content -Raw -Path $DatabaseFile | ConvertFrom-Json
        }
        return $Database
    }
}
# Write Script Database File
function Write-Database
{
    param([string]$DatabaseFile, $Database)
    end
    {
        ConvertTo-Json $Database | Out-File -FilePath $DatabaseFile -Force
    }
}
# Get Maintenance Window
function Get-MaintenanceWindow
{
    param([Parameter(Mandatory=$false)][string]$NowTime,
          [Parameter(Mandatory=$true)][string]$StartTime,
          [Parameter(Mandatory=$true)][string]$EndTime)
    end
    {
        if($NowTime.Length -eq 0){$Now = [DateTime]::Now}else{
            $Now = [datetime]::ParseExact($NowTime,"HH:mm:ss",$null)
        }
        $Start = [datetime]::ParseExact($StartTime,"HH:mm:ss",$null)
        $End = [datetime]::ParseExact($EndTime,"HH:mm:ss",$null)
        if($Start -gt $End){
            if($Now -lt $End){
                log -msg "- Inside Maintenance Window for reducing Hosts | (Now: $Now) (Start: $Start) and (End: $($End.AddDays(1)))" -type Success
                return $true
            }
            $End = $End.AddDays(1)
        }
        [boolean]$Result = (($Start -le $Now) -and ($Now -le $End))
        if($Result){log -msg "- Inside Maintenance Window for reducing Hosts | (Now: $Now) (Start: $Start) and (End: ($End)" -type Success} 
            else {log -msg "- Outside Maintenance Window for reducing Hosts | (Now: $Now) (Start: $Start) and (End: ($End)" -type Error}
        return $Result
    }
}
# Replace Database Item
function Update-Database
{
    param($Database, $DatabaseEntry, $DatabaseFile)
    end
    {
        $DatabaseEntry.LastModified = [datetime]::Now
        [PSCustomObject[]]$Database = $Database |? {$_.ServerName -ne $DatabaseEntry.ServerName}
        $Database += $DatabaseEntry
        Write-Database -DatabaseFile $DatabaseFile -Database $Database
        return $Database
    }
}
# Authenticate to AAD
function Authenticate-AAD
{
    param([Parameter(Mandatory=$true)][string]$Environment,
          [Parameter(Mandatory=$true)][string]$AppId,
          [Parameter(Mandatory=$true)][string]$TenantId,
          [Parameter(Mandatory=$true)][string]$Thumbprint,
          [Parameter(Mandatory=$true)][string]$ManagementEndpoint,
          [Parameter(Mandatory=$true)][string]$SubscriptionId)
    end
    {
        if($Environment -eq "Public") {
            $context = Connect-AzAccount -ServicePrincipal -ApplicationId $AppId -Tenant $TenantId -CertificateThumbprint $Thumbprint 
        } else {
            Add-AzEnvironment -Name "AzureStackUser" -ArmEndpoint $ManagementEndpoint
            $AuthEndpoint = (Get-AzEnvironment -Name "AzureStackUser").ActiveDirectoryAuthority.TrimEnd('/')
            $context = Connect-AzAccount -ServicePrincipal -ApplicationId $AppId -Tenant $TenantId -CertificateThumbprint $Thumbprint 
            Add-AzAccount -EnvironmentName "AzureStackUser" -TenantId $TenantId -CertificateThumbprint $Thumbprint -ApplicationId $AppId -Subscription $SubscriptionId
        }
    }
}
# Start Azure Virtual Machine
function Start-VirtualMachine
{
    param([Parameter(Mandatory=$true)][string]$VMResourceGroup,
          [Parameter(Mandatory=$true)][string]$Name)
    end
    {
        $Name = $Name.Split(".")[0]
        log -msg "- Powering Up ($Name)" -type Information

        Authenticate-AAD -Environment $Environment -AppId $AppId -TenantId $TenantId -Thumbprint $Thumbprint `
                            -ManagementEndpoint $ManagementEndpoint -SubscriptionId $SubscriptionId | Out-Null

        $vm = Get-AzVM -Name $Name -status -ResourceGroupName $VMResourceGroup
        if($vm.Statuses[1].DisplayStatus -ne "VM running") { 
            log -msg "- Virtual Machine ($Name) was stopped / attempting start" -type Information
            $result = start-AzVM -Name $Name -ResourceGroupName $vm.ResourceGroupName 
            log -msg "- Virtual Machine ($Name) was started / result ($($result.Status))" -type Information
            return $result
        } else {
            log -msg "- Virtual Machine ($Name) was not deallocated)" -type Information
        }
    }
}
# Stop Azure Virtual Machine
function Stop-VirtualMachine
{
    param([Parameter(Mandatory=$true)][string]$VMResourceGroup,
          [Parameter(Mandatory=$true)][string]$Name)
    end
    {
        $Name = $Name.Split(".")[0]
        log -msg "- Powering Down ($Name)" -type Information

        Authenticate-AAD -Environment $Environment -AppId $AppId -TenantId $TenantId -Thumbprint $Thumbprint `
                            -ManagementEndpoint $ManagementEndpoint -SubscriptionId $SubscriptionId | Out-Null

        $vm = Get-AzVM -Name $Name -status -ResourceGroupName $VMResourceGroup
        if($vm.Statuses[1].DisplayStatus -ne "VM deallocated") { 
            $result = Stop-AzVM -Name $Name -ResourceGroupName $vm.ResourceGroupName -Force
            log -msg "- Virtual Machine ($Name) was stopped / result ($($result.Status))" -type Information
            return $result
        } else {
            log -msg "- Virtual Machine ($Name) was not running)" -type Information
        }
        
    }
}
# Test Session Host
function Test-Sessionhost
{
    param([Parameter(Mandatory=$true)][string]$Name,
          [Parameter(Mandatory=$true)][int]$RetryAttempts)
    end
    {
        # Start the loop and check for a true response over $RetryAttempts attempts
        log -msg "- Testing ($Name)" -type Information
        $attempts = 0
        do
        {
            $result = Test-NetConnection -ComputerName $Name -CommonTCPPort RDP -WarningAction SilentlyContinue
            if($result.TcpTestSucceeded -eq $false) { 
                log -msg "- RDP Closed. Retry Attempt $($RetryAttempts-$attempts)/$RetryAttempts"
            }
            $attempts++
        }
        until( ($result.TcpTestSucceeded -eq $true) -or ($attempts -eq $RetryAttempts) )
        # If the loop counter is hit send an alert. Session Host can not support incoming RDP connections and exit
        if( $result.TcpTestSucceeded -eq $false ) { 
            if( $attempts -eq $RetryAttempts ) {
                log -msg "- Session Host ($Name) can not support incoming RDP connections after retry $RetryAttempts attempts."
            } else {
                log -msg "- Session Host ($Name) offline."
            }
            return $false
        } else {
            return $true
        }
    }
}

# Main routine

<# Notification that the script is starting #>
log -msg "Starting ***************************************************************************************"
log -msg "Assessing whether collection capacity should be expanded."

<# 
    Purpose: Store Primary Broker
    Note: This is a database / wmi / network call and has a cost (make once / use many)
#>
if($HA -eq $true) {
    $PrimaryBroker = (Get-RDConnectionBrokerHighAvailability -ConnectionBroker $Broker).ActiveManagementServer
} else {
    $PrimaryBroker = (Get-RDServer -ConnectionBroker $Broker -Role RDS-CONNECTION-BROKER).Server
}
log -msg "Stored Primary Broker ($($PrimaryBroker))"

<# 
    Purpose: Store Session Hosts for the collection
    Note: This is a database call (has a cost. make it once and use results many.)
#>
$SessionHosts = Get-RDSessionHost -ConnectionBroker $PrimaryBroker -CollectionName $CollectionName
log -msg "Stored Collection Session Hosts ($($SessionHosts.Length))"

<# 
    Purpose: Store User Sessions
    Note: This is a database call (has a cost. make it once and use results many.)
#>
$Sessions = Get-RDUserSession -ConnectionBroker $PrimaryBroker -CollectionName $CollectionName
log -msg "Stored User Sessions ($($Sessions.Count))"

<#  Get a Unique List of Session Hosts #>
$ActiveHosts = ($Sessions | Sort-Object { $_.HostServer } -Unique).HostServer
log -msg "Active Hosts ($(($Sessions | Sort-Object { $_.HostServer } -Unique).Count))"

<#  Store number of active hosts which have exceeded $maxsessions #>
$MaxedHosts = 0
ForEach($ActiveHost in $ActiveHosts) {
    if( ($Sessions | Where-Object { $_.HostServer -eq $ActiveHost }).Count -ge $MaxSessions ){
        $MaxedHosts += 1
    }
}
log -msg "Session Hosts ($($MaxedHosts)) Exceeding maximum sessions ($($MaxSessions))"

<#  Check all nodes which are allowing connections are online #>
$OnlineHosts = $SessionHosts | Where-Object { $_.NewConnectionAllowed -eq 'Yes' }
ForEach($OnlineHost in $OnlineHosts) {
    $Result = Test-Sessionhost -Name $OnlineHost.SessionHost -RetryAttempts 1
    if(!$Result){
        Start-VirtualMachine -Name $($OnlineHost.SessionHost) -VMResourceGroup $VMResourceGroup
    }
}
log -msg "Online Hosts ($($OnlineHosts.Count))"

  <#  
     Purpose: Compare Maxed Hosts against Session Hosts which allow new connections to determine if
                another session host should be made available to users in the collection
     Notes: Logically. 2 x Enabled Session Hosts in the pool and 2 x Max Session Hosts = Power-up / Allow additional Host
#>
$Provision = $false
if( ($SessionHosts | Where-Object { $_.NewConnectionAllowed -eq 'Yes' }).count -eq $MaxedHosts ) { $Provision = $true }
log -msg "Provision more capacity ($Provision)"

<#  
    Purpose: Check that are available hosts available in the pool to meet demand.
    Notes: 
#>
$AvailableHosts = ($SessionHosts | Where-Object { $_.NewConnectionAllowed -eq "No" })
if($Provision -eq $true) {
    if($AvailableHosts -eq $null) { 
        log -msg "No More Available Session Hosts - Exiting" -writeEventLog $true -type Error
        exit 1
    }
}
log -msg "Available Hosts ($($AvailableHosts.Count))"

<# 
     Purpose:  Determine and populate the AvailableHost variable
     Note: If there is only a single entry then its not an arry
#>
if($Provision -eq $true) { 
    if($AvailableHosts.Count -eq 1){
        $AvailableHost = $AvailableHosts
    } else {
        $AvailableHost = $AvailableHosts[0]
    }
}

<# 
     Purpose:  Check if the host is still online and if it is allow new connections and exit otherwise power the host up
     Note: The host may still be in draining mode and this is the quickes
#>
if($Provision -eq $true) {
    log -msg "Checking where Session Host ($($AvailableHost.SessionHost)) is online and draining."
    $Result = Test-Sessionhost -Name $AvailableHost.SessionHost -RetryAttempts 1
    if($Result){
        # If the session host is online, allow new connections and exit (no more activity!)
        Set-RDSessionHost -ConnectionBroker $PrimaryBroker -SessionHost ($AvailableHost.SessionHost) -NewConnectionAllowed Yes
        log -msg "Session Host ($($AvailableHost.SessionHost)) with blocked connections is still online. Allowing Connections - Exit" -type Success
        exit 0
    } else {
        log -msg "Session Host ($($AvailableHost.SessionHost)) with blocked connections is offline and will need to be powered up."
        Start-VirtualMachine -Name $($AvailableHost.SessionHost) -VMResourceGroup $VMResourceGroup
        $RetryAttempts = 15
        $Result = Test-Sessionhost -Name $AvailableHost.SessionHost -RetryAttempts $RetryAttempts
        if(!$Result){
            log -msg "Session Host ($($AvailableHost.SessionHost)) can not support incoming RDP connections after retry $RetryAttempts attempts - Exit" -type Error
            exit 1
        } else {
            log -msg "Session Host ($($AvailableHost.SessionHost)) is online. Allowing Connections"
            Set-RDSessionHost -ConnectionBroker $PrimaryBroker -SessionHost ($AvailableHost.SessionHost) -NewConnectionAllowed Yes
            log -msg "Session Host ($($AvailableHost.SessionHost)) is online.Connections Allowed - Exit" -type Success
            exit 0
        }
    }
}

<# Notification that the farm was not expanded #>
log -msg "The collection was not expanded. Assessing whether collection capacity should be reduced."

<# 
     Purpose: Check if reductions should be running and if not exit the run.
     Notes: This needs to take the simple 24 hr hour formats and convert them to a datetime that can be used to create the
                maintenance window
#>
$MaintenanceWindows = Get-MaintenanceWindow -StartTime $StartTime -EndTime $EndTime
if(!$MaintenanceWindows){exit 0}

<# 
    Purpose: Store / Database File
    Notes: This Database File will store / update session hosts in the database file
#>
$Database = Get-Database -DatabaseFile $DatabaseFile
if(!$Database){ log -msg "Initialising Database ($DatabaseFile) for the first time."; $Database = @()}

<# 
     Purpose: Update Database File
     Notes: Ensure the file contains all valid session hosts
#>
log -msg "Updating and processing entries in the capacity database."
# Add missing hosts to database
foreach($SessionHost in $SessionHosts){
    $Present = $Database |? {$_.ServerName -eq $SessionHost.SessionHost}
    if($Present -eq $null){
        $Server = New-ServerObject -ServerName $SessionHost.SessionHost `
                                    -Blocked $false `
                                    -TotalOfflineHours 0 `
                                    -MonthlyOfflineHours 0 `
                                    -LastModified ([datetime]::Now.ToString())
        $Database += $Server
    }
}
#Remove missing hosts from database
$MissingEntries = $Database |? {($_.ServerName) -notin $SessionHosts.SessionHost}
foreach($MissingEntry in $MissingEntries) {
    $Database = $Database |? {$_.ServerName -ne $MissingEntry.ServerName}
}
# Update the Database
Write-Database -DatabaseFile $DatabaseFile -Database $Database
log -msg "Updated the database."
<# 
     Purpose: Check draining file and process hosts
     Notes:
#>
$DrainingHosts = $Database |? {$_.Draining -eq $true}
log -msg "Draining Hosts ($($DrainingHosts.Count))."
if($DrainingHosts.count -gt 0)
{
    foreach($DrainingHost in $DrainingHosts)
    {
        log -msg "Session Host ($($DrainingHost.ServerName)) already draining."  
        # If the host no longer has any sessions then it can be finally removed .ServerName
        if( ($Sessions | Where-Object { $_.HostServer -eq $DrainingHost }).Count -eq 0 )
        {
            log -msg "Session Host ($($DrainingHost.ServerName)) no longer has any active sessions (drain complete)"
            # Block Connections
            Set-RDSessionHost -ConnectionBroker $PrimaryBroker -SessionHost ($DrainingHost.SessionHost) -NewConnectionAllowed No
            log -msg "Blocked new connections on Session Host ($($DrainingHost.ServerName))"
            # Stop VM
            $result = Stop-VirtualMachine -Name $DrainingHost.ServerName -VMResourceGroup $VMResourceGroup
            log -msg "Powered Off Session Host ($($DrainingHost.ServerName))"
            # Clear out the entry from the tracking file if the shutdown was successful
            if($result.Status -eq "Succeeded")
            {
                $DatabaseEntry = $Database |? {$_.ServerName -eq $DrainingHost.ServerName}
                $DatabaseEntry.Draining = $false
                $Database = Update-Database -Database $Database -DatabaseEntry $DatabaseEntry -DatabaseFile $DatabaseFile
                exit 0
                log -msg "Removed the Session Host ($($DrainingHost.ServerName)) from the tracking file."
            }
        }
    }
}
 <#  
     Purpose: Check for all hosts that have blocked connections that are still online
     Notes: This will handle scenarios where a change was made outside the script.
#>
<#  Check all nodes which are allowing connections are offline #>
log -msg "Check Blocked Hosts are Offline"
$BlockedHosts = $SessionHosts | Where-Object { $_.NewConnectionAllowed -eq 'No' }
ForEach($BlockedHost in $BlockedHosts) {
    $Result = Test-Sessionhost -Name $BlockedHost.SessionHost -RetryAttempts 1
    if($Result){
        Stop-VirtualMachine -Name $($BlockedHost.SessionHost) -VMResourceGroup $VMResourceGroup
    }
}
log -msg "Blocked Hosts ($($BlockedHosts.Count))"

 <#  
     Purpose: Determine how many session hosts have less sessions than the $minsession variable
     Notes: This will also set the list in descending format. This is cosmetic and will attempt
                to power off the highest number session host first.
#>
$IdleHosts = @()
ForEach($SessionHost in ($SessionHosts | Where-Object { $_.NewConnectionAllowed -eq 'Yes' })) {
    if( ($Sessions | Where-Object { $_.HostServer -eq $ActiveHost }).Count -le $MinSession `
            -or ($Sessions | Where-Object { $_.HostServer -eq $ActiveHost }) -eq $null) {
        $IdleHosts += $SessionHost
    }
}
# Sort In Descending Order (Highest VDI Server Number first)
$IdleHosts = $IdleHosts | Sort-Object SessionHost
log -msg "Idle Hosts ($($IdleHosts.Count))"

<#  
    Purpose: Check for at least as many hosts as $minhosts
    Notes:
#>
$DeProvision = $false
if($IdleHosts.Count -gt $MinHosts) { $DeProvision = $true } else {
    log -msg "Minimum Session Hosts ($MinHosts) Reached - Exit" -type Success
    exit 0
}


<#  
    Purpose: Check for at least as many hosts as $minhosts
    Notes:
#>
$DeProvision = $false
if($IdleHosts.Count -eq 1) { 
    log -msg "There must be a single session host online - Exit" -type Error
    exit 0 } 
 else {
    $DeProvision = $true
}

<#  
    Purpose: Remove the lowest minhost and loop through the rest
    Notes:
#>
$IdleHosts = $IdleHosts | Select-Object -Skip $MinHosts

<#  
     Purpose: If there are enough idle session hosts then drain them or power them off
     Notes: This routine has two outcomes. Power Down the VM (no sessions) or add to tracking database (still draining)
#>
foreach($IdleHost in $IdleHosts) {
    if( ($DeProvision -eq $true) ) {
        if( ($Sessions | Where-Object { $_.HostServer -eq $IdleHost.SessionHost }).Count -eq 0 )
        {
            # If the session host is online, allow new connections and exit (no more activity!)
            Set-RDSessionHost -ConnectionBroker $PrimaryBroker -SessionHost ($IdleHost.SessionHost) -NewConnectionAllowed No
            log -msg "Session Host ($($IdleHost.SessionHost)) Connections are now Blocked"
            log -msg "Session Host ($($IdleHost.SessionHost)) has no active sessions. Powering Down."
            # Stop VM
            $result = Stop-VirtualMachine -Name $IdleHost.SessionHost -VMResourceGroup $VMResourceGroup
            if($result.Status -eq "Succeeded")
            {
                log -msg "Powered Off Session Host ($($IdleHost.SessionHost))" -type Success
            }
        }
        else
        {
            # Add 
            log -msg "Session Host ($($IdleHost.SessionHost)) has active sessions. Can't be powered off."
            $DatabaseEntry = $Database |? {$_.ServerName -eq $IdleHost.SessionHost}
            $DatabaseEntry.Draining = $true
            $Database = Update-Database -Database $Database -DatabaseEntry $DatabaseEntry -DatabaseFile $DatabaseFile
            log -msg "Session Host ($($IdleHost.SessionHost)) has been added to the database" -type Success
        }
    }
}
# Routine Complete
log -msg "Procedure complete." -type Success