# This file should be included from ..\init_SQLServerLab.ps1

$deploymentRoot = "$PSScriptRoot\..\Deployment"

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
    Users         = @(
        [PSCustomObject]@{
            Name        = 'User'
            Password    = 'P#ssw0rd'
            LocalGroups = @('Remote Desktop Users', 'Remote Management Users')
        }
        [PSCustomObject]@{
            Name        = 'SQLAdmin'
            Password    = 'P#ssw0rd'
            ADGroups    = @('SQLAdmins')
            LocalGroups = @('Remote Desktop Users', 'Remote Management Users', 'Administrators')
        }
        [PSCustomObject]@{
            Name        = 'SQLUser'
            Password    = 'P#ssw0rd'
            ADGroups    = @('SQLUsers')
            LocalGroups = @('Remote Desktop Users', 'Remote Management Users')
        }
    )
    DCIPAddress   = $null        # Will be set during the deployment
}

$vmConfig = [ordered]@{
    DC = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
#        VMSize       = 'Standard_B2s_v2'  # Get-AzComputeResourceSku | Where-Object { $_.Locations -contains $location }  https://azureprice.net/
        VMSize       = 'Standard_B2s'
        Script_A     = "$PSScriptRoot\Deployment_A.ps1"
        Script_B     = "$PSScriptRoot\Deployment_B_DC.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules      = @(
            'PSFramework'
        )
        FileServerDriveLetter = 'C'
    }
    CLIENT = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
#        VMSize       = 'Standard_E2s_v6'
        VMSize       = 'Standard_B2s_v2'
        Script_A     = "$PSScriptRoot\Deployment_A.ps1"
        Script_B     = $null
        Script_C     = "$deploymentRoot\Deployment_C_CLIENT.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            'powershell-core'
            'sql-server-management-studio'
            'git'
            'vscode'
        )
        Modules      = @(
            'PSFramework'
            'dbatools'
        )
        DelegateComputer = @(
            'SQL01'
            'SQL02'
#            'SQL2019'
#            'SQL2022'
        )
#        SQLServer    = [PSCustomObject]@{
#            SqlInstance  = 'SQL2022\DBATOOLS'
#            InstancePath = 'C:\SQLServer'
#            AdminAccount = @(
#                "$($domainConfig.NetbiosName)\SQLAdmins"
#            )
 #       }
    }
    SQL01 = [PSCustomObject]@{
        SourceImage   = 'SQLServer2022'
        VMSize        = 'Standard_B2s'
        Script_A      = "$PSScriptRoot\Deployment_A.ps1"
        Status        = $statusConfig
        Domain        = $domainConfig 
        Packages      = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules       = @(
            'PSFramework'
        )
    }
    SQL02 = [PSCustomObject]@{
        SourceImage   = 'SQLServer2022'
        VMSize        = 'Standard_B2s'
        Script_A      = "$PSScriptRoot\Deployment_A.ps1"
        Status        = $statusConfig
        Domain        = $domainConfig 
        Packages      = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules       = @(
            'PSFramework'
        )
    }
#    SQL2019 = [PSCustomObject]@{
#        SourceImage   = 'SQLServer2019'
#        VMSize        = 'Standard_B4s_v2'
#        Script_A      = "$PSScriptRoot\Deployment_A.ps1"
#        Script_B      = $null
#        Script_C      = "$deploymentRoot\Deployment_C_SQL20xx.ps1"
#        ScriptBlock_C = "$deploymentRoot\Deployment_C_SQL20xx_ScriptBlock.ps1"
#        Status        = $statusConfig
#        Domain        = $domainConfig 
#        Packages      = @(
#            'notepadplusplus'
#            'powershell-core'
#        )
#        Modules       = @(
#            'PSFramework'
#        )
#    }
#    SQL2022 = [PSCustomObject]@{
#        SourceImage   = 'SQLServer2022'
#        VMSize        = 'Standard_B4s_v2'
#        Script_A      = "$PSScriptRoot\Deployment_A.ps1"
#        Script_B      = $null
#        Script_C      = "$deploymentRoot\Deployment_C_SQL20xx.ps1"
#        ScriptBlock_C = "$deploymentRoot\Deployment_C_SQL20xx_ScriptBlock.ps1"
#        Status        = $statusConfig
#        Domain        = $domainConfig 
#        Packages      = @(
#            'notepadplusplus'
#            'powershell-core'
#        )
#        Modules       = @(
#            'PSFramework'
#            'dbatools'
#        )
#    }
}

# These are "global" variables, so that they can be used in other commands
$userCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.UserName)", (ConvertTo-SecureString -String $domainConfig.UserPassword -AsPlainText -Force))
$adminCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)", (ConvertTo-SecureString -String $domainConfig.AdminPassword -AsPlainText -Force))
$sqlUserCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\SQLUser", (ConvertTo-SecureString -String $domainConfig.UserPassword -AsPlainText -Force))
$sqlAdminCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\SQLAdmin", (ConvertTo-SecureString -String $domainConfig.AdminPassword -AsPlainText -Force))
