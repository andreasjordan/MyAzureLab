Param (
    [string[]]$StartComputerName,
    [string[]]$ConnectComputerName
)

<# Sample code to run this init script:
. .\init_SQLServerLabMini.ps1
. .\init_SQLServerLabMini.ps1 -Start DC, CLIENT -Connect CLIENT
#>

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script needs pwsh 7"
}

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'SQLServerLabMini'
$location          = 'North Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of the resource group
Show-MyAzureLabResourceGroupInfo

# Read the configuration
. .\SQLServerLabMini\set_vm_config.ps1

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



# To use the PowerShell module ActiveDirectory in the CLIENT:
# Install-WindowsFeature -Name "RSAT-AD-PowerShell"

# I try to use the "normal" account for most of the tests and developments:
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.User

# On the SQL2022 only the domain admin is able to connect via RDP:
Start-MyAzureLabRDP -ComputerName SQL2022 -Credential $credentials.Admin

# For testing dbatools, currently use admin account on CLIENT:
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.Admin


# Just in case:
$psSession = New-MyAzureLabSession -ComputerName CLIENT -Credential $credentials.User
$psSession | Remove-PSSession






# Tasks to create and remove virtual maschines:
###############################################

# Show the configuration 
$vmConfig | ConvertTo-Json

# Uses Microsoft.PowerShell.ConsoleGuiTools and needs some other object structures (so work in progress):
$vmConfig | Show-ObjectTree

# Create the VMs
. .\SQLServerLabMini\create_VMs.ps1

# Connect to client

# Just once:
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f

Start-MyAzureLabRDP -ComputerName DC -Credential $credentials.Admin

Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.User
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.Admin
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.SQLUser
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $credentials.SQLAdmin

Start-MyAzureLabRDP -ComputerName SQL2022 -Credential $credentials.SQLAdmin



# To remove all virtual maschines:
##################################

Remove-MyAzureLabVM -All -Verbose






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
