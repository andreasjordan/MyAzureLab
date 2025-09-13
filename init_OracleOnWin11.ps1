Param (
    [string[]]$StartComputerName,
    [string[]]$ConnectComputerName
)

<# Sample code to run this init script:
. .\init_OracleOnWin11.ps1
. .\init_OracleOnWin11.ps1 -Start All -Connect CLIENT1
#>

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script needs pwsh 7"
}

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'OracleOnWin11'
$location          = 'North Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of the resource group
Show-MyAzureLabResourceGroupInfo

# Read the configuration
. .\OracleOnWin11\set_vm_config.ps1

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



Start-MyAzureLabRDP -ComputerName DC -Credential $credentials.Admin
Start-MyAzureLabRDP -ComputerName CLIENT1 -Credential $credentials.Admin
Start-MyAzureLabRDP -ComputerName CLIENT2 -Credential $credentials.Admin



# Tasks to create and remove virtual maschines:
###############################################

# Read the configuration
. .\OracleOnWin11\set_vm_config.ps1

# Create the VMs
. .\OracleOnWin11\create_VMs.ps1




Start-MyAzureLabRDP -ComputerName DC -Credential $credentials.Admin

Start-MyAzureLabRDP -ComputerName CLIENT1 -Credential $credentials.Admin
Start-MyAzureLabRDP -ComputerName CLIENT2 -Credential $credentials.Admin



Remove-MyAzureLabVM -ComputerName DC
Remove-MyAzureLabVM -ComputerName CLIENT1
Remove-MyAzureLabVM -ComputerName CLIENT2

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
