Param (
    [string[]]$StartComputerName,
    [string[]]$ConnectComputerName
)

<# Sample code to run this init script:
. .\init_HyperVLab.ps1
. .\init_HyperVLab.ps1 -Start BASE -Connect BASE
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
