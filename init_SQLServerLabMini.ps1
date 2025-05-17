$ErrorActionPreference = 'Stop'

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'SQLServerLabMini'
$location          = 'West Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Only used for the STATUS server
$timezone = 'Europe/Berlin'

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

# I try to use the "normal" account for most of the tests and developments:
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $userCredential

# On the SQL2022 only the domain admin is able to connect via RDP:
Start-MyAzureLabRDP -ComputerName SQL2022 -Credential $adminCredential


# Just in case:
$psSession = New-MyAzureLabSession -ComputerName CLIENT -Credential $userCredential
$psSession | Remove-PSSession






# Tasks to create and remove virtual maschines:
###############################################

# Read the configuration
. .\SQLServerLabMini\set_vm_config.ps1

# Create the VMs
. .\SQLServerLabMini\create_VMs.ps1

# Configure computer account of SQL Server to be able to register SPNs
$session = New-MyAzureLabSession -ComputerName DC -Credential $adminCredential
Invoke-Command -Session $session -ScriptBlock { 
    $result = dsacls.exe "CN=SQL2022,CN=Computers,DC=dom,DC=local" /G "SELF:RPWP;servicePrincipalName"
    $result[-1]
}
$session | Remove-PSSession

# Make sure the SQL Server services are started
$session = New-MyAzureLabSession -ComputerName SQL2022 -Credential $adminCredential
Invoke-Command -Session $session -ScriptBlock { 
    Start-Service -Name 'MSSQLSERVER'
    Start-Service -Name 'MSSQL$DBATOOLS'
}
$session | Remove-PSSession


# Connect to client

# Just once:
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f

Start-MyAzureLabRDP -ComputerName CLIENT -Credential $userCredential
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $adminCredential
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $sqlUserCredential
Start-MyAzureLabRDP -ComputerName CLIENT -Credential $sqlAdminCredential

Start-MyAzureLabRDP -ComputerName SQL2022 -Credential $sqlAdminCredential

# Save PSCredential at client

$session = New-MyAzureLabSession -ComputerName CLIENT -Credential $userCredential
Write-PSFMessage -Level Host -Message 'Session ist started'
Invoke-Command -Session $session -ScriptBlock { 
    # We have to wait for the logon of the RDP session to complete
    $target = [datetime]::Now.AddSeconds(15)
    while ([datetime]::Now -lt $target) {
        try {
            $using:userCredential | Export-Clixml -Path $HOME\MyCredential.xml
            break
        } catch {
            Write-Warning "Fehler: $_"
            Start-Sleep -Seconds 1
        }
    }
}
$session | Remove-PSSession


# To use the PowerShell module ActiveDirectory in the CLIENT:
# Install-WindowsFeature -Name "RSAT-AD-PowerShell"





Restart-MyAzureLabVM -ComputerName SQL2022


ipmo dbatools

$cred = Get-Credential 
Test-DbaConnection -SqlInstance SQL2022, SQL2022\DBATOOLS -SqlCredential $cred

Get-EventLog -ComputerName SQL2022 -LogName Application -Source 'MSSQL$DBATOOLS' -Message *SPN*

Restart-Computer -ComputerName SQL2022

Get-EventLog -ComputerName SQL2022 -LogName Application -Source 'MSSQL$DBATOOLS' -Message *SPN* -Newest 3
Get-EventLog -ComputerName SQL2022 -LogName Application -Source MSSQLSERVER -Message *SPN* -Newest 3

Get-DbaService -ComputerName SQL2022 -Type Engine

Stop-DbaService -ComputerName SQL2022 -InstanceName MSSQLSERVER -Type Engine

Stop-DbaService -ComputerName SQL2022 -InstanceName DBATOOLS -Type Engine -Force
Start-DbaService -ComputerName SQL2022 -InstanceName DBATOOLS -Type Engine

Install-WindowsFeature -Name "RSAT-AD-PowerShell"

Set-DbaNetworkConfiguration -SqlInstance sql2022\dbatools -StaticPortForIPAll 14333

Set-DbaNetworkConfiguration -SqlInstance sql2022\dbatools -DynamicPortForIPAll -RestartService











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
New-MyAzureLabKeyVault -Credential $initCredential
# Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force

# Creating network and security group
New-MyAzureLabNetwork -HomeIP $homeIP
# Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName | Remove-AzVirtualNetwork -Force
# Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName | Remove-AzNetworkSecurityGroup -Force
