Param (
    [string[]]$CreateComputerName,
    [string[]]$StartComputerName,
    [string[]]$ConnectComputerName
)

<# Sample code to run this init script:
. .\init_HyperVLab.ps1
. .\init_HyperVLab.ps1 -Create BASE -Connect BASE
. .\init_HyperVLab.ps1 -Start BASE -Connect BASE

Stop-MyAzureLabResourceGroup
#>

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script needs pwsh 7"
}

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'HyperVLab'
$location          = 'North Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of the resource group
Show-MyAzureLabResourceGroupInfo

# Configuration for the lab
$labConfig = @{
    LabScript            = @{
        Name    = 'TestingDbatools.ps1'
        Content = Get-Content -Path ".\HyperVLab\TestingDbatools.ps1" -Raw
    }
    ISODownloads         = @(
        @{ Name = 'Windows2025'   ; URL = $Env:MyWIN2025URL ; FileName = 'WindowsServer2025_x64_EN_Eval.iso' }
        @{ Name = 'SQLServer2025' ; URL = $Env:MySQL2025URL ; FileName = 'SQLServer2025-x64-ENU.iso' }
        @{ Name = 'SQLServer2022' ; URL = $Env:MySQL2022URL ; FileName = 'enu_sql_server_2022_developer_edition_x64_dvd_7cacf733.iso' }
        @{ Name = 'SQLServer2019' ; URL = $Env:MySQL2019URL ; FileName = 'en_sql_server_2019_developer_x64_dvd_e5ade34a.iso' }
    )
    EnvironmentVariables = @{
        MyStatusURL        = $env:MyStatusURL
        MyLabName          = 'TestingDbatools'
        MyLabNetworkBase   = '192.168.3'
        MyLabAdminUser     = 'Admin'
        MyLabAdminPassword = 'P@ssw0rd'
        MyLabDomainName    = 'ordix.local'
    }
}

# Create VMs
if ($CreateComputerName) {
    foreach ($computerName in $CreateComputerName) {
        . .\HyperVLab\create_$computerName.ps1
    }
}

# Start VMs
if ($StartComputerName) {
    if ($StartComputerName -eq 'All') {
        Start-MyAzureLabResourceGroup    
    } else {
        Start-MyAzureLabResourceGroup -OnlyComputerName $StartComputerName
    }
}

# Connect to VMs (always use the admin credential in this case)
if ($ConnectComputerName) {
    Start-Sleep -Seconds 30
    foreach ($computerName in $ConnectComputerName) {
        Start-MyAzureLabRDP -ComputerName $computerName -Credential $initCredential
    }
}

# Try to set TLS 1.2 fix to avoid errors with Azure modules (The SSL connection could not be established / An error occurred while sending the request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Don't do anything else
break

# To suppress the warnings about breaking changes:
# Update-AzConfig -DisplayBreakingChangeWarning $false

# To suppress information about cheaper regions:
# Update-AzConfig -DisplayRegionIdentified $false


# Daily tasks if the lab is fully set up:
#########################################

Start-MyAzureLabResourceGroup

Stop-MyAzureLabResourceGroup

Start-MyAzureLabRDP -ComputerName BASE -Credential $initCredential

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
$psSession | Remove-PSSession

Invoke-MyAzureLabCommand -ComputerName BASE -Credential $initCredential -ArgumentList $labConfig -ScriptBlock {
    param($config)
    foreach ($envVar in $config.EnvironmentVariables.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($envVar.Key, $envVar.Value, 'Machine')
    }
}

init.ps1:
Import-Module -Name AutomatedLab
Import-Lab -Name $env:MyLabName -NoValidation
Start-LabVM -ComputerName DC -Wait
Start-Sleep -Seconds 30
Start-LabVM -All -Wait
Start-Sleep -Seconds 60
mstsc /v:$env:MyLabNetworkBase.20



$RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$ValueName  = 'InitLabScript'
$ScriptPath = 'C:\LabScripts\init.ps1'
$PowerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

$CommandLine = "`"$PowerShell`" -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

$current = Get-ItemProperty -Path $RunKeyPath -Name $ValueName -ErrorAction SilentlyContinue
if ($null -eq $current) {
    New-ItemProperty -Path $RunKeyPath -Name $ValueName -PropertyType String -Value $CommandLine -Force | Out-Null
    Write-Host "Created HKCU Run entry '$ValueName' -> $CommandLine"
} elseif ($current.$ValueName -ne $CommandLine) {
    Set-ItemProperty -Path $RunKeyPath -Name $ValueName -Value $CommandLine -Force
    Write-Host "Updated HKCU Run entry '$ValueName' -> $CommandLine"
} else {
    Write-Host "HKCU Run entry '$ValueName' already set. No changes made."
}




Invoke-Command -ComputerName DC -ScriptBlock {
    $dnsRoot = (Get-ADDomain).DNSRoot
    Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $dnsRoot -HostNameAlias fci01.$dnsRoot -Name app01
    Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $dnsRoot -HostNameAlias sql03.$dnsRoot -Name app02
}



# Next steps for improving the lab:
# * Start VMs when BASE starts
# * RDP into ADMIN01 on login to BASE
# * Include "reg add "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v DisableHardwareAcceleration /t REG_DWORD /d 1 /f" as it helps
# * Chang default keyboard layout to DE in ADMIN01



# Tasks to create and remove virtual maschine:
##############################################

. .\HyperVLab\create_BASE.ps1

Start-MyAzureLabRDP -ComputerName BASE -Credential $initCredential



# Tasks to resize the virtual maschine:
#######################################

$vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name BASE_VM
$result = $vm | Stop-AzVM -Force
$result.Status  # Should be 'Succeeded'
$vm.HardwareProfile.VmSize = 'Standard_E4s_v6'
$result = Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm
$result.IsSuccessStatusCode  # Should be True
$result = $vm | Start-AzVM
$result.Status  # Should be 'Succeeded'




# To remove all virtual maschines:
##################################

Remove-MyAzureLabVM -All -Verbose


# The path where the logging is saved:
######################################

Get-PSFConfigvalue -FullName PSFramework.Logging.FileSystem.LogPath 


# Adding Azure SQL Database to the lab:
######################################

# ------------------------------
# Inputs you set
# ------------------------------
$LogicalServerName   = "sqllab$(Get-Random)"   # must be globally unique
$DatabaseName        = "sqllabdb"
$ApplyFreeOffer      = $true                   # try to use free tier
$AutoPauseMinutes    = 15                      # minimum supported, keeps cost down
$MinVCore            = 0.5                     # serverless lower bound for GP
$MaxVCore            = 1                       # tiny top end for tests

# ------------------------------
# Create (or reuse) logical server
# ------------------------------
$sqlServer = Get-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -ErrorAction SilentlyContinue
if (-not $sqlServer) {
    $sqlServer = New-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -Location $location -SqlAdministratorCredentials $initCredential
}

# ------------------------------
# Lock down firewall to current public IP only
# (change to your office IP if needed)
# ------------------------------
$fwRule = Get-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -FirewallRuleName AllowHome -ErrorAction SilentlyContinue
if ($fwRule) {
    $null = Set-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -FirewallRuleName AllowHome -StartIpAddress $homeIP -EndIpAddress $homeIP
} else {
    $null = New-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -FirewallRuleName AllowHome -StartIpAddress $homeIP -EndIpAddress $homeIP
}

# ------------------------------
# Create the database (serverless GP)
# Try free offer first; fall back to paid serverless if not applicable.
# ------------------------------
$commonDbParams = @{
    ResourceGroupName = $resourceGroupName
    ServerName        = $LogicalServerName
    DatabaseName      = $DatabaseName
    Edition           = "GeneralPurpose"
    ComputeModel      = "Serverless"           # vCore-based serverless
    ComputeGeneration = "Gen5"
    VCore             = [int][math]::Ceiling($MaxVCore)  # required by cmdlet; cap at max
    AutoPauseDelayInMinutes = $AutoPauseMinutes
    MinimumCapacity   = $MinVCore
    MaxSizeBytes      = 32GB                   # stays within free limit / small storage
    BackupStorageRedundancy = "Local"          # cheapest for a test lab
}

$db = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $LogicalServerName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue
if (-not $db) {
    if ($ApplyFreeOffer) {
        try {
            $db = New-AzSqlDatabase @commonDbParams -UseFreeLimit -FreeLimitExhaustionBehavior "Pause" -ErrorAction Stop
        } catch {
            Write-Warning "Free offer not applied (maybe quota/region/subscription). Falling back to paid serverless."
            $db = New-AzSqlDatabase @commonDbParams
        }
    } else {
        $db = New-AzSqlDatabase @commonDbParams
    }
}

# Output essentials
$sqlServer | Select-Object ServerName, FullyQualifiedDomainName, Location
$db     | Select-Object DatabaseName, Edition, Status, CurrentServiceObjectiveName



Remove-AzSqlDatabase -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -DatabaseName $DatabaseName
Remove-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName -FirewallRuleName AllowHome
Remove-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $LogicalServerName


# The following commands are only used for initial setup or final destruction:
##############################################################################

# Creating resource group
$null = New-AzResourceGroup -Name $resourceGroupName -Location $location
# $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
# Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }

# Creating key vault and certificate
New-MyAzureLabKeyVault
# Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force

# Creating network and security group
New-MyAzureLabNetwork -HomeIP $homeIP
# Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName | Remove-AzVirtualNetwork -Force
# Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName | Remove-AzNetworkSecurityGroup -Force
