$ErrorActionPreference = 'Stop'
Import-Module -Name PSFramework    # Install-Module -Name PSFramework   # Update-Module -Name PSFramework
Import-Module -Name Az             # Install-Module -Name Az            # Update-Module -Name Az
Import-Module -Name Posh-SSH       # Install-Module -Name Posh-SSH      # Update-Module -Name Posh-SSH
. .\MyAzureLab.ps1

# The following script is not publicly available, as it containes my personal setting.
# Just search for "$Env:MyAzure" in this script to find all the variables that I set there.
. .\MyAzureLabEnvironment.ps1        

$PSDefaultParameterValues = @{ "*-MyAzureLab*:EnableException" = $true }

<#

This Skript will setup my lab with Azure virtual maschines for the multi database environment based on docker.

It takes about an hour.

It will connect to Azure with
* a given acount name (`$accountId`)
* a given subscription (`$subscriptionName`)

It will then create the following objects.

A [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell) with
* a given name (`$resourceGroupName`)
* in a given location (`$location`)

A [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts) with
* the name "KeyVault<10 digit random number>"
* a self signed certificate named "<name of resource group>Certificate" to support connecting to the virtual maschines via WinRM

A [virtual network](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) with
* the name "VirtualNetwork"
* the address prefix "10.0.0.0/16"
* a subnet with the name "Default" and the address prefix "10.0.0.0/24"
* the IP address "10.0.0.10" for the domain controller

A [network security group](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) with
* the name "NetworkSecurityGroup"
* rules to allow communication from my home address to the network for RDP (port 3389), SSH (port 22) and WinRM (port 5986)

A set of [virtual maschines](https://docs.microsoft.com/en-us/azure/virtual-machines/):
* A server with
  * the name "MULTIDB"
  * Linux Ubuntu 22.04
  * Docker
  * PowerShell
* A workstation with
  * the name "CLIENT"
  * Windows 10
  * to be the only maschine to RDP in and do the lab work from there

#>

# Test for needed environment variables
if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription -and $Env:MyAzureInitialAdmin -and $Env:MyAzureInitialPassword) {
    Write-PSFMessage -Level Verbose -Message 'Environment is set'
} else {
    throw "Not all needed environment variables are set"
}

# Will be used with Connect-AzAccount
$privateAzureAccountParameters = @{
    AccountId    = $Env:MyAzureAccountId
    Subscription = $Env:MyAzureSubscription
}

# Name of resource group and location
# Will be used by MyAzureLab commands
$resourceGroupName = 'MultiDB'
$location = 'North Central US'


# Will be used by MyAzureLab commands
$initialAdmin    = $Env:MyAzureInitialAdmin     # Will be used when creating the virtual maschines
$initialPassword = $Env:MyAzureInitialPassword  # Will be used when creating the virtual maschines and for the certificate

$secretPassword = ConvertTo-SecureString -String $initialPassword -AsPlainText -Force
$credential = [PSCredential]::new($initialAdmin, $secretPassword)



# Part 1: Connecting

Write-PSFMessage -Level Host -Message 'Connecting to Azure'
$account = Connect-AzAccount @privateAzureAccountParameters
Write-PSFMessage -Level Verbose -Message "Connected to Azure with account '$($account.Context.Account.Id)' and subscription '$($account.Context.Subscription.Name)' in tenant '$($account.Context.Tenant.Id)'"



Remove-MyAzureLabVM -ComputerName CLIENT -Verbose
New-MyAzureLabVM -ComputerName CLIENT -SourceImage Windows10 -NoDomain -Verbose
#$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name CLIENT_VM -Force
#$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name CLIENT_VM
#$session = New-MyAzureLabSession -ComputerName CLIENT -Credential $credential -Timeout 30 -Verbose


# $session
