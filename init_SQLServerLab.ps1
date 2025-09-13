Param (
    [string[]]$StartComputerName,
    [string[]]$ConnectComputerName
)

<# Sample code to run this init script:
. .\init_SQLServerLab.ps1
. .\init_SQLServerLab.ps1 -Start DC, CLIENT -Connect CLIENT
#>

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script needs pwsh 7"
}

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'SQLServerLab'
$location          = 'North Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of the resource group
Show-MyAzureLabResourceGroupInfo

# Read the configuration
. .\SQLServerLab\set_vm_config.ps1

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
        Start-MyAzureLabRDP -ComputerName $computerName -Credential $credentials.Admin
    }
}

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

Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.Admin


Start-MyAzureLabRDP -ComputerName SERVER -Credential $initCredential

$psSession = New-MyAzureLabSession -ComputerName SERVER -Credential $initCredential
$psSession | Remove-PSSession



# Tasks to create and remove virtual maschines:
###############################################

# Read the configuration
. .\SQLServerLab\set_vm_config.ps1

# Create the VMs
. .\SQLServerLab\create_VMs.ps1




##########
Write-PSFMessage -Level Host -Message 'Part 5: Connecting to client'
##########

# Just once:
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f

Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.SQLAdmin





# Testing dbatools
##################

Start-MyAzureLabRDP -ComputerName SQL01 -Credential $credentials.Admin


# powershell as administrator on SQL01:
choco install git vscode sql-server-management-studio --confirm --limitoutput --no-progress
Copy-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft SQL Server Tools*\SQL Server Management Studio*.lnk' -Destination C:\Users\Public\Desktop
Restart-Computer -Force

Install-Module -Name Pester -Force -SkipPublisherCheck -MaximumVersion 4.99
Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck -MaximumVersion 1.18.2
Install-Module -Name dbatools.library -Force

$null = New-Item -Path C:\GitHub\dataplat -ItemType Directory
Push-Location -Path C:\GitHub\dataplat
git clone --quiet https://github.com/dataplat/dbatools.git
git clone --quiet https://github.com/dataplat/appveyor-lab.git
Pop-Location

$ErrorActionPreference = 'Stop'
Import-Module -Name C:\GitHub\dataplat\dbatools
$PSDefaultParameterValues['*-Dba*:EnableException'] = $true
$PSDefaultParameterValues['*-Dba*:Confirm'] = $false
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

$config = Get-Content -Path C:\Deployment\config.txt | ConvertFrom-Json

$version = 2022

# Get-DbaInstalledPatch.Tests.ps1 braucht einen installiertes CU
Get-ChildItem -Path \\fs\Software\SQLServer\CU\SQLServer$version* | Sort-Object Name | Select-Object -Last 1 | Remove-Item

$instanceParams = @{
    Feature            = 'Engine'
    Version            = $version
    Configuration      = @{
        SqlMaxMemory          = '2048'
    } 
    AuthenticationMode = 'Mixed'
    IFI                = $true
    Path               = '\\fs\Software\SQLServer\ISO'
    UpdateSourcePath   = '\\fs\Software\SQLServer\CU'
}
$null = Install-DbaInstance @instanceParams -SqlInstance localhost -ProductID '11111-00000-00000-00000-00000'
$null = Install-DbaInstance @instanceParams -SqlInstance localhost\dbatools2
$null = Install-DbaInstance @instanceParams -SqlInstance localhost\dbatools3


# $updateResult = Update-DbaInstance -ComputerName localhost -Path \\fs\Software\SQLServer\CU
# Restart
$sqlInstance = 'localhost', 'localhost\dbatools2', 'localhost\dbatools3'
$null = Set-DbaLogin -SqlInstance $sqlInstance -Login sa -SecurePassword (ConvertTo-SecureString -String 'Passw0rd!' -AsPlainText -Force)
$null = Set-DbaSpConfigure -SqlInstance $sqlInstance -Name IsSqlClrEnabled -Value 1
$null = Set-DbaSpConfigure -SqlInstance $sqlInstance -Name ClrStrictSecurity -Value 0
$null = Set-DbaNetworkConfiguration -SqlInstance $sqlInstance -EnableProtocol NamedPipes -RestartService

$null = Set-DbaNetworkConfiguration -SqlInstance $sqlInstance[1] -StaticPortForIPAll 14333 -RestartService

$null = Enable-DbaAgHadr -SqlInstance $sqlInstance[2] -Force
$server = Connect-DbaInstance -SqlInstance $sqlInstance[2]
$server.Query("IF NOT EXISTS (select * from sys.symmetric_keys where name like '%DatabaseMasterKey%') CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<StrongPassword>'")
$server.Query("IF EXISTS ( SELECT * FROM sys.tcp_endpoints WHERE name = 'End_Mirroring') DROP ENDPOINT endpoint_mirroring")
$server.Query("CREATE CERTIFICATE dbatoolsci_AGCert WITH SUBJECT = 'AG Certificate'")







# To remove all virtual maschines:
##################################

Remove-MyAzureLabVM -All -Verbose


# The path where the logging is saved:
######################################

Get-PSFConfigvalue -FullName PSFramework.Logging.FileSystem.LogPath 



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



#########################


# Load Balancer Frontend IP
$net = Get-AzVirtualNetwork -Name VirtualNetwork -ResourceGroupName $resourceGroupName
$frontendIP = New-AzLoadBalancerFrontendIpConfig -Name "FrontendConfig" `
    -PrivateIpAddress "10.0.0.101" `
    -SubnetId (Get-AzVirtualNetworkSubnetConfig -Name Default -VirtualNetwork $net).Id

# Backend Pool
$backendPool = New-AzLoadBalancerBackendAddressPoolConfig -Name "BackendPool"

# Health Probe
$probe = New-AzLoadBalancerProbeConfig -Name "HealthProbe" `
    -Protocol Tcp -Port 1433 -IntervalInSeconds 5 -ProbeCount 2

# Load Balancing Rule mit Floating IP
$lbRule = New-AzLoadBalancerRuleConfig -Name "SQLRule" `
    -FrontendIpConfiguration $frontendIP `
    -BackendAddressPool $backendPool `
    -Probe $probe `
    -Protocol Tcp -FrontendPort 1433 -BackendPort 1433 `
    -EnableFloatingIP

# Load Balancer erstellen
$lb = New-AzLoadBalancer -ResourceGroupName $resourceGroupName -Name "MyILB" `
    -Location $location `
    -FrontendIpConfiguration $frontendIP `
    -BackendAddressPool $backendPool `
    -Probe $probe `
    -LoadBalancingRule $lbRule

# NICs der VMs dem Backend Pool hinzufügen
$nic1 = Get-AzNetworkInterface -Name "SQL01_Interface" -ResourceGroupName $resourceGroupName
$nic2 = Get-AzNetworkInterface -Name "SQL02_Interface" -ResourceGroupName $resourceGroupName

$nic1.IpConfigurations[0].LoadBalancerBackendAddressPools = $lb.BackendAddressPools
$nic2.IpConfigurations[0].LoadBalancerBackendAddressPools = $lb.BackendAddressPools

Set-AzNetworkInterface -NetworkInterface $nic1
Set-AzNetworkInterface -NetworkInterface $nic2
