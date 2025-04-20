$ErrorActionPreference = 'Stop'

. .\MyAzureLab.ps1

# Name of resource group and location
# Will be used by MyAzureLab commands (so these are "global" variables)
$resourceGroupName = 'SQLServerLabMini2'
$location          = 'North Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate
$initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))

# Only used for the STATUS server
$timezone = 'Europe/Berlin'

# Show state of resource group
Show-MyAzureLabResourceGroupInfo

# Don't do anything else
break

# To suppress the warnings about breaking changes:
# Update-AzConfig -DisplayBreakingChangeWarning $false


# Daily tasks if the lab is fully set up:
#########################################

Start-MyAzureLabResourceGroup

Stop-MyAzureLabResourceGroup


Start-MyAzureLabRDP -ComputerName SERVER -Credential $initCredential

$psSession = New-MyAzureLabSession -ComputerName SERVER -Credential $initCredential
$psSession | Remove-PSSession



# Tasks to create and remove virtual maschines:
###############################################

# Read the configuration
. .\SQLServerLabMini\set_vm_config.ps1


# To keep track of the duration
$deploymentStart = [datetime]::Now

# The following was part of: Invoke-MyAzureLabPart1 -Config $config

Write-PSFMessage -Level Host -Message 'Step 2: Setting up virtual maschines'
foreach ($computerName in $vmConfig.Keys) {
    Write-PSFMessage -Level Host -Message "Creating virtual maschine $computerName"
    New-MyAzureLabVM -ComputerName $computerName -SourceImage $vmConfig.$computerName.SourceImage -VMSize $vmConfig.$computerName.VMSize -Credential $initCredential -TrustedLaunch -EnableException
}


Write-PSFMessage -Level Host -Message 'Step 3: Setting up deployment monitoring'
New-MyAzureLabVM -ComputerName STATUS -SourceImage Ubuntu22 -VMSize Standard_B2s -Credential $initCredential -EnableException
Write-PSFMessage -Level Host -Message 'Configuring virtual maschine STATUS'
Set-MyAzureLabSFTPItem -ComputerName STATUS -Credential $initCredential -Path .\status.ps1 -Destination "/home/$($initCredential.UserName)" -Force -EnableException

$installStatusApi = @(
    "sudo timedatectl set-timezone $timezone"
    "echo '@reboot sudo pwsh /home/$($initCredential.UserName)/status.ps1 &' > /tmp/crontab"
    'crontab /tmp/crontab'
    'rm /tmp/crontab'
    "nohup sudo pwsh /home/$($initCredential.UserName)/status.ps1 &"
)
$null = Invoke-MyAzureLabSSHCommand -ComputerName STATUS -Credential $initCredential -Command $installStatusApi -EnableException
# Does not finish and has to be stopped with Ctrl-C


$statusApiPrivateIP = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "STATUS_Interface").IpConfigurations[0].PrivateIpAddress
$statusConfig.Uri = "http://$statusApiPrivateIP/status"
$domainConfig.DCIPAddress = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "DC_Interface").IpConfigurations[0].PrivateIpAddress





##########
Write-PSFMessage -Level Host -Message 'Part 2: Setting up the active directory domain'
##########

# Renaming the virtual maschines
# Installing software
# Setting up PowerShell
# Installing PowerShell modules
# Setting up domain
# Setting up file server on domain controller

$partStartedAt = [datetime]::Now
foreach ($computerName in $vmConfig.Keys) {
    Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
    Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_A -Config $vmConfig.$computerName -verbose
}
Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt

    



##########
Write-PSFMessage -Level Host -Message 'Part 3: Setting up SQL Server resources'
##########

# Creating AD users
# Filling file server with sql server sources
# Setting up CredSSP

$partStartedAt = [datetime]::Now
foreach ($computerName in $vmConfig.Keys) {
    if ($vmConfig.$computerName.Script_B) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_B -Config $vmConfig.$computerName
    }
}
Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt




##########
Write-PSFMessage -Level Host -Message 'Part 4: Setting up SQL Server instances'
##########

$partStartedAt = [datetime]::Now
foreach ($computerName in $vmConfig.Keys) {
    if ($vmConfig.$computerName.Script_C) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_C -Config $vmConfig.$computerName
    }
    if ($vmConfig.$computerName.ScriptBlock_C) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        $script = Get-Content -Path $vmConfig.$computerName.ScriptBlock_C -Raw
        $scriptblock = [scriptblock]::Create($script)
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -ScriptBlock $scriptblock
    }
}
Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt



Remove-MyAzureLabVM -ComputerName STATUS



##########
Write-PSFMessage -Level Host -Message 'Part 5: Connecting to client'
##########

# Just once:
# reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f

Start-MyAzureLabRDP -ComputerName CLIENT -Credential $userCredential


##########
Write-PSFMessage -Level Host -Message 'Part 6: Saving PSCredential at client'
##########

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


$deploymentDuration = [datetime]::Now - $deploymentStart
Write-PSFMessage -Level Host -Message "Finished deployment after $([int]$deploymentDuration.TotalMinutes) minutes"












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
