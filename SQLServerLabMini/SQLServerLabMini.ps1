[CmdletBinding()]
Param(
    [switch]$GetStatus,
    [switch]$StartDeployment,
    [int[]]$OnlyDeploymentParts
)

$ErrorActionPreference = 'Stop'

if ($OnlyDeploymentParts) {
    $StartDeployment = $false
}

if ($PSScriptRoot) {
    $scriptPath = $PSScriptRoot
} else {
    $scriptPath = '.'
}
. $scriptPath\..\MyAzureLab.ps1

$PSDefaultParameterValues['*-MyAzureLab*:EnableException'] = $true
$PSDefaultParameterValues['*-PSF*:EnableException'] = $true


# Name of resource group and location
# Will be used by MyAzureLab commands (so these are global variables)
$global:resourceGroupName = 'SQLServerLabMini'
$global:location          = 'West Europe'

# Name and password of the initial account
$initUser     = 'initialAdmin'     # Will be used when creating the virtual maschines
$initPassword = 'initialP#ssw0rd'  # Will be used when creating the virtual maschines and for the certificate

# Configuration of the target domain
# Will be used later in this script
$statusConfig = [PSCustomObject]@{
    Uri           = $null        # Will be set during the deployment
}
$domainConfig = [PSCustomObject]@{
    Name          = 'dom.local'
    NetbiosName   = 'DOM'
    AdminName     = 'Admin'
    AdminPassword = 'P#ssw0rd'
    UserName      = 'User'
    UserPassword  = 'P#ssw0rd'
    DCIPAddress   = $null        # Will be set during the deployment
}
$config = @{
    DC = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
        VMSize       = 'Standard_B2ms'
        Script_A     = "$scriptPath\Deployment_A.ps1"
        Script_B     = "$scriptPath\Deployment_B_DC.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            '7zip'
            'powershell-core'
        )
        Modules      = @(
            'PSFramework'
            'dbatools'
        )
        FileServerDriveLetter = 'C'
    }
    CLIENT = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
        VMSize       = 'Standard_B2ms'
        Script_A     = "$scriptPath\Deployment_A.ps1"
        Script_B     = "$scriptPath\Deployment_B_CLIENT.ps1"
#        Script_C     = "$scriptPath\Deployment_C_CLIENT.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            '7zip'
            'powershell-core'
            'sql-server-management-studio'
            'vscode'
            'vscode-powershell'
            'git'
        )
        Modules      = @(
            'PSFramework'
            'dbatools'
        )
        DelegateComputer = @(
            'SQL2022'
        )
        SQLServer    = [PSCustomObject]@{
            SqlInstance  = 'SQL2022\DBATOOLS'
            InstancePath = 'C:\SQLServer'
            AdminAccount = @(
                "$($domainConfig.NetbiosName)\SQLAdmins"
            )
        }
    }
    SQL2022 = [PSCustomObject]@{
        SourceImage   = 'SQLServer2022'
        VMSize        = 'Standard_B2ms'
        Script_A      = "$scriptPath\Deployment_A.ps1"
        Script_B      = "$scriptPath\Deployment_B_SQL.ps1"
        ScriptBlock_C = "$scriptPath\Deployment_C_SQL20xx.ps1"
        Status        = $statusConfig
        Domain        = $domainConfig 
        Packages      = @(
            'notepadplusplus'
            '7zip'
            'powershell-core'
        )
        Modules       = @(
            'PSFramework'
        )
    }
}


# These are global variables, so that they can be used in other commands
$global:initCredential = [PSCredential]::new($initUser, (ConvertTo-SecureString -String $initPassword -AsPlainText -Force))
$global:userCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.UserName)", (ConvertTo-SecureString -String $domainConfig.UserPassword -AsPlainText -Force))
$global:adminCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)", (ConvertTo-SecureString -String $domainConfig.AdminPassword -AsPlainText -Force))


if ($GetStatus) {
    if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
        Write-PSFMessage -Level Host -Message "Getting status for VMs in resource group $resourceGroupName."
        Get-AzVM -ResourceGroupName $resourceGroupName -Status | Format-Table -Property Name, PowerState
    } else {
        Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
    }
    return
}

if (-not ($StartDeployment -or $OnlyDeploymentParts)) {
    Write-PSFMessage -Level Verbose -Message "No deployment selected."
    return
}

# To keep track of the duration
$deploymentStart = [datetime]::Now

if ($StartDeployment -or $OnlyDeploymentParts -contains 1) {
    Invoke-MyAzureLabPart1 -Config $config
}

$statusApiPrivateIP = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "STATUS_Interface").IpConfigurations[0].PrivateIpAddress
$statusConfig.Uri = "http://$($statusApiPrivateIP):8000/status"
$domainConfig.DCIPAddress = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "DC_Interface").IpConfigurations[0].PrivateIpAddress

if ($StartDeployment -or $OnlyDeploymentParts -contains 2) {
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
    foreach ($computerName in $config.Keys) {
        Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
        Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $config.$computerName.Script_A -Config $config.$computerName
    }
    Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt
}

if ($StartDeployment -or $OnlyDeploymentParts -contains 3) {
    ##########
    Write-PSFMessage -Level Host -Message 'Part 3: Setting up SQL Server resources'
    ##########

    # Creating AD users
    # Filling file server with sql server sources
    # Setting up CredSSP

    $partStartedAt = [datetime]::Now
    foreach ($computerName in $config.Keys) {
        if ($config.$computerName.Script_B) {
            Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
            Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $config.$computerName.Script_B -Config $config.$computerName
        }
    }
    Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt
}

if ($StartDeployment -or $OnlyDeploymentParts -contains 4) {
    ##########
    Write-PSFMessage -Level Host -Message 'Part 4: Setting up SQL Server instances'
    ##########

    $partStartedAt = [datetime]::Now
    foreach ($computerName in $config.Keys) {
        if ($config.$computerName.Script_C) {
            Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
            Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -Path $config.$computerName.Script_C -Config $config.$computerName
        }
        if ($config.$computerName.ScriptBlock_C) {
            Write-PSFMessage -Level Host -Message "Configuring virtual maschine $computerName"
            $script = Get-Content -Path $config.$computerName.ScriptBlock_C -Raw
            $scriptblock = [scriptblock]::Create($script)
            Invoke-MyAzureLabDeployment -ComputerName $computerName -Credential $initCredential -ScriptBlock $scriptblock
        }
    }
    Wait-MyAzureLabDeploymentCompletion -OnlyStatusAfter $partStartedAt
}

if ($StartDeployment -or $OnlyDeploymentParts -contains 5) {
    ##########
    Write-PSFMessage -Level Host -Message 'Part 5: Connecting to client'
    ##########

    # Just once:
    # reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f

    Start-MyAzureLabRDP -ComputerName CLIENT -Credential $userCredential
}

if ($StartDeployment -or $OnlyDeploymentParts -contains 6) {
    ##########
    Write-PSFMessage -Level Host -Message 'Part 6: Saving PSCredential at client'
    ##########

    $session = New-MyAzureLabSession -ComputerName CLIENT -Credential $userCredential
    Invoke-Command -Session $session -ScriptBlock { 
        # We have to wait for the logon of the RDP session to complete
        $target = [datetime]::Now.AddSeconds(15)
        while ([datetime]::Now -lt $target) {
            try {
                $using:userCredential | Export-Clixml -Path $HOME\MyCredential.xml
                break
            } catch {
                Start-Sleep -Seconds 1
            }
        }
    }
    $session | Remove-PSSession
}

$deploymentDuration = [datetime]::Now - $deploymentStart
Write-PSFMessage -Level Host -Message "Finished deployment after $([int]$deploymentDuration.TotalMinutes) minutes"
