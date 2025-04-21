$ErrorActionPreference = 'Stop'

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'JustForFun'
$location = 'North Europe'

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

Start-MyAzureLabResourceGroup

Stop-MyAzureLabResourceGroup


Start-MyAzureLabRDP -ComputerName WIN11 -Credential $initCredential

$psSession = New-MyAzureLabSession -ComputerName SERVER -Credential $initCredential
$psSession | Remove-PSSession

$session = New-MyAzureLabSSHSession -ComputerName ALMA9 -Credential $initCredential
$null = Invoke-SSHCommand -SSHSession $session -Command 'pwd' -ShowStandardOutputStream 


# Tasks to create and remove virtual maschines:
###############################################


# Standard_B2s:    2 vCPU /  4 GB RAM / 0,0496 Euro/h / no TrustedLaunch
# Standard_B2s_v2  2 vCPU /  8 GB RAM / 0,0926 Euro/h / TrustedLaunch
# Standard_B4s_v2: 4 vCPU / 16 GB RAM / 0,1862 Euro/h / TrustedLaunch
# Standard_E4s_v6: 4 vCPU / 32 GB RAM / 0,4445 Euro/h / TrustedLaunch

New-MyAzureLabVM -ComputerName WIN11 -SourceImage Windows11 -VMSize Standard_B2s_v2 -Credential $initCredential -TrustedLaunch

New-MyAzureLabVM -ComputerName SRV2022 -SourceImage WindowsServer2022 -VMSize Standard_B2s_v2 -Credential $initCredential -TrustedLaunch
New-MyAzureLabVM -ComputerName SRV2025 -SourceImage WindowsServer2025 -VMSize Standard_B2s_v2 -Credential $initCredential -TrustedLaunch

New-MyAzureLabVM -ComputerName SQL2019 -SourceImage SQLServer2019 -VMSize Standard_B4s_v2 -Credential $initCredential -TrustedLaunch
New-MyAzureLabVM -ComputerName SQL2022 -SourceImage SQLServer2022 -VMSize Standard_B4s_v2 -Credential $initCredential -TrustedLaunch

New-MyAzureLabVM -ComputerName UBUNTU22 -SourceImage Ubuntu22 -VMSize Standard_B2s -Credential $initCredential
New-MyAzureLabVM -ComputerName UBUNTU24 -SourceImage Ubuntu24 -VMSize Standard_B2s -Credential $initCredential

New-MyAzureLabVM -ComputerName ALMA8 -SourceImage AlmaLinux8 -VMSize Standard_B2s -Credential $initCredential
New-MyAzureLabVM -ComputerName ALMA9 -SourceImage AlmaLinux9 -VMSize Standard_B2s -Credential $initCredential


Start-MyAzureLabRDP -ComputerName SRV2025 -Credential $initCredential
# To setup WSL2 (not supported on WIN11, tested on SRV2025):
# Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
# wsl --install
# wsl --install






Remove-MyAzureLabVM -ComputerName WIN11 
Remove-MyAzureLabVM -ComputerName SRV2022 
Remove-MyAzureLabVM -ComputerName SRV2025

Remove-MyAzureLabVM -All -Verbose




# The following commands are only used for initial setup or final destruction:
##############################################################################

# Creating resource group
$null = New-AzResourceGroup -Name $resourceGroupName -Location $location
# $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
# Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }

# Creating key vault and certificate
New-MyAzureLabKeyVault -Credential $initCredential
# Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force

# Creating network and security group
New-MyAzureLabNetwork -HomeIP $homeIP
# Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName | Remove-AzVirtualNetwork -Force
# Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName | Remove-AzNetworkSecurityGroup -Force
