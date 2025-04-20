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
$vmConfig = @{
    DC = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
        VMSize       = 'Standard_B2s_v2'  # Get-AzComputeResourceSku | Where-Object { $_.Locations -contains $location }  https://azureprice.net/
        Script_A     = "$PSScriptRoot\Deployment_A.ps1"
        Script_B     = "$PSScriptRoot\Deployment_B_DC.ps1"
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
        VMSize       = 'Standard_B2s_v2'
        Script_A     = "$PSScriptRoot\Deployment_A.ps1"
        Script_B     = "$PSScriptRoot\Deployment_B_CLIENT.ps1"
        Script_C     = "$PSScriptRoot\Deployment_C_CLIENT.ps1"
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
#        VMSize        = 'Standard_B4s_v2'
        VMSize        = 'Standard_E4s_v6'
        Script_A      = "$PSScriptRoot\Deployment_A.ps1"
        Script_B      = "$PSScriptRoot\Deployment_B_SQL.ps1"
        Script_C      = "$PSScriptRoot\Deployment_C_SQL20xx.ps1"
        ScriptBlock_C = "$PSScriptRoot\Deployment_C_SQL20xx_ScriptBlock.ps1"
        Status        = $statusConfig
        Domain        = $domainConfig 
        Packages      = @(
            'notepadplusplus'
            '7zip'
            'powershell-core'
            'vscode'
            'vscode-powershell'
            'git'
        )
        Modules       = @(
            'PSFramework'
        )
    }
}

# These are "global" variables, so that they can be used in other commands
$userCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.UserName)", (ConvertTo-SecureString -String $domainConfig.UserPassword -AsPlainText -Force))
$adminCredential = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)", (ConvertTo-SecureString -String $domainConfig.AdminPassword -AsPlainText -Force))
