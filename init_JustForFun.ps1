$ErrorActionPreference = 'Stop'

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands
$resourceGroupName = 'JustForFun'
$location = 'Germany West Central'  # nearer
#$location = 'North Europe'          # cheaper

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Show state of resource group
Show-MyAzureLabResourceGroupInfo

# Don't do anything else
break

# Maybe needed more than once?
Update-AzConfig -DisplayBreakingChangeWarning $false


# Daily tasks if the lab is fully set up:
#########################################

Start-MyAzureLabResourceGroup

Stop-MyAzureLabResourceGroup


Start-MyAzureLabRDP -ComputerName SERVER -Credential $initCredential

$psSession = New-MyAzureLabSession -ComputerName SERVER -Credential $initCredential
$psSession | Remove-PSSession



# Tasks to create and remove virtual maschines:
###############################################


New-MyAzureLabVM -ComputerName SERVER -SourceImage WindowsServer2025WSL -VMSize Standard_E4s_v5 -Credential $initCredential

New-MyAzureLabVM -ComputerName SERVER -SourceImage WindowsServer2025WSL -VMSize Standard_E4s_v5 -Credential $initCredential -TrustedLaunch


# To setup WSL2:
# Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
# wsl --install
# wsl --install







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
