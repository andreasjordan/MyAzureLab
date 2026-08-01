# This file should be included from ..\init_SQLServerLabMini.ps1

# To keep track of the duration
$deploymentStart = [datetime]::Now


##########
Write-PSFMessage -Level Host -Message 'Part 1: Setting up virtual maschines'
##########

foreach ($computerName in $vmConfig.Keys) {
    Write-PSFMessage -Level Host -Message "Creating virtual maschine $computerName"
    New-MyAzureLabVM -ComputerName $computerName -SourceImage $vmConfig.$computerName.SourceImage -VMSize $vmConfig.$computerName.VMSize -Credential $initCredential -TrustedLaunch -EnableException
}
if ($Env:MyStatusURL) {
    $statusConfig.Uri = $Env:MyStatusURL
    $domainConfig.DCIPAddress = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "DC_Interface").IpConfigurations[0].PrivateIpAddress
} else {
    # The following also sets $statusConfig.Uri and $domainConfig.DCIPAddress
    Write-PSFMessage -Level Host -Message "Creating virtual maschine STATUS"
    New-MyAzureLabStatusVM -EnableException
}


##########
Write-PSFMessage -Level Host -Message 'Part 2: Setting up the active directory domain'
##########

# Setting up CredSSP and WinRM
# Installing software
# Setting up PowerShell
# Installing PowerShell modules
# Setting up domain
# Creating AD users on domain controller
# Setting up file server on domain controller

$statusBefore = Get-MyAzureLabStatus
$dispatched = @( )
foreach ($computerName in $vmConfig.Keys) {
    Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
    Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_A -Config $vmConfig.$computerName -EnableException
    $dispatched += $computerName
}
Write-PSFMessage -Level Host -Message "Waiting 2 minutes"
Start-Sleep -Seconds 120
Wait-MyAzureLabDeploymentCompletion -ComputerName $dispatched -StatusBefore $statusBefore -EnableException


##########
Write-PSFMessage -Level Host -Message 'Part 3: Setting up SQL Server resources'
##########

# Filling file server with sql server sources

$statusBefore = Get-MyAzureLabStatus
$dispatched = @( )
foreach ($computerName in $vmConfig.Keys) {
    if ($vmConfig.$computerName.Script_B) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_B -Config $vmConfig.$computerName -EnableException
        $dispatched += $computerName
    }
}
Write-PSFMessage -Level Host -Message "Waiting 2 minutes"
Start-Sleep -Seconds 120
Wait-MyAzureLabDeploymentCompletion -ComputerName $dispatched -StatusBefore $statusBefore -EnableException


##########
Write-PSFMessage -Level Host -Message 'Part 4: Setting up SQL Server instances'
##########

$statusBefore = Get-MyAzureLabStatus
$dispatched = @( )
foreach ($computerName in $vmConfig.Keys) {
    if ($vmConfig.$computerName.Script_C) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $vmConfig.$computerName.Script_C -Config $vmConfig.$computerName -EnableException
        # Only Script_C runs as a scheduled task and reports to the status api,
        # ScriptBlock_C runs right here and returns when it is done
        $dispatched += $computerName
    }
    if ($vmConfig.$computerName.ScriptBlock_C) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        $script = Get-Content -Path $vmConfig.$computerName.ScriptBlock_C -Raw
        $scriptblock = [scriptblock]::Create($script)
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -ScriptBlock $scriptblock -Config $vmConfig.$computerName -EnableException
    }
}
Write-PSFMessage -Level Host -Message "Waiting 2 minutes"
Start-Sleep -Seconds 120
Wait-MyAzureLabDeploymentCompletion -ComputerName $dispatched -StatusBefore $statusBefore -EnableException

if (-not $Env:MyStatusURL) {
    Write-PSFMessage -Level Host -Message "Removing virtual maschine STATUS"
    Remove-MyAzureLabVM -ComputerName STATUS -EnableException
}

$deploymentDuration = [datetime]::Now - $deploymentStart
Write-PSFMessage -Level Host -Message "Finished deployment after $([int]$deploymentDuration.TotalMinutes) minutes"
