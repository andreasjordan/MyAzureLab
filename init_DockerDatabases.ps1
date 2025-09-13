<#

This Skript will setup my lab with Azure virtual maschines for the multi database environment based on docker.

It will connect to Azure with
* a given acount name (`$accountId`)
* a given subscription (`$subscriptionName`)

It will then create the following objects.

A [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell) with
* a given name (`$resourceGroupName`)
* in a given location (`$location`)

A [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts) with
* the name "KeyVault<10 digit random number>"
* a self signed certificate named "<name of resource group>Certificate" to support the windows virtual maschines

A [virtual network](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) with
* the name "VirtualNetwork"
* the address prefix "10.0.0.0/16"
* a subnet with the name "Default" and the address prefix "10.0.0.0/24"

A [network security group](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) with
* the name "NetworkSecurityGroup"
* rules to allow communication from my home address to the network for RDP (port 3389), SSH (port 22) and WinRM (port 5986)

A set of [virtual maschines](https://docs.microsoft.com/en-us/azure/virtual-machines/):
* A server with
  * the name "DATABASES"
  * Linux Ubuntu 22.04
  * Docker
  * PowerShell
* A workstation with
  * the name "CLIENT"
  * Windows 11
  * PowerShell 7
  * VSCode
  * Repository PowerShell-for-DBAs

#>

$ErrorActionPreference = 'Stop'

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'DockerDatabases'
$location          = 'West Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of the resource group
Show-MyAzureLabResourceGroupInfo

# Don't do anything else
break

# To suppress the warnings about breaking changes:
# Update-AzConfig -DisplayBreakingChangeWarning $false

# To suppress information about cheaper regions:
# Update-AzConfig -DisplayRegionIdentified $false


# Daily tasks if the lab is fully set up:
#########################################

# Import this file as the first task to set all needed variables:
. .\init_dockerDatabases.ps1


Start-MyAzureLabResourceGroup

Stop-MyAzureLabResourceGroup


Start-MyAzureLabRDP -ComputerName CLIENT -Credential $initCredential


# To connect via SSH in another session (my preferred option):
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "DATABASES_PublicIP").IpAddress
"ssh $initUser@$ipAddress" | Set-Clipboard


# Just in case:
$psSession = New-MyAzureLabSession -ComputerName CLIENT -Credential $initCredential
$psSession | Remove-PSSession


# Get private IP address of DATABASES (should return 10.0.0.4):
(Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "DATABASES_Interface").IpConfigurations[0].PrivateIpAddress



# Tasks to create and remove virtual maschines:
###############################################

# To keep track of the duration
$deploymentStart = [datetime]::Now


# Setting up virtual maschine DATABASES
# In case I need to recreate: Remove-MyAzureLabVM -ComputerName DATABASES

# If your setup is stable and you just want create the server like last time:
. .\DockerDatabases\create_DATABASES.ps1


# Setting up virtual maschine CLIENT
# In case I need to recreate: Remove-MyAzureLabVM -ComputerName CLIENT

# If your setup is stable and you just want create the server like last time:
. .\DockerDatabases\create_CLIENT.ps1


$deploymentDuration = [datetime]::Now - $deploymentStart
Write-PSFMessage -Level Host -Message "Finished deployment after $([int]$deploymentDuration.TotalMinutes) minutes"



# Some code for DATABASES:

# Show the IP address of the created virtual maschine DATABASES:
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "DATABASES_PublicIP").IpAddress
$ipAddress

# Connect via SSH in the current session:
ssh $initUser@$ipAddressyes

# To connect via SSH in another session (my preferred option):
"ssh $initUser@$ipAddress" | Set-Clipboard

# Execute these lines inside of the SSH session to import some data:
pwsh ./GitHub/PowerShell-for-DBAs/PowerShell/03_ImportSampleDataFromJson.ps1
pwsh ./GitHub/PowerShell-for-DBAs/PowerShell/04_ImportSampleDataFromStackexchange.ps1
pwsh ./GitHub/PowerShell-for-DBAs/PowerShell/05_ImportSampleGeographicData.ps1





# To remove all virtual maschines:
##################################

Remove-MyAzureLabVM -All






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
