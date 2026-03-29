# This file should be included from ..\init_OracleOnWin11.ps1

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
            Name        = 'OraAdmin'
            Password    = 'P#ssw0rd'
            ADGroups    = @('OraAdmins')
            LocalGroups = @('Remote Desktop Users', 'Remote Management Users', 'Administrators')
        }
        [PSCustomObject]@{
            Name        = 'OraUser'
            Password    = 'P#ssw0rd'
            ADGroups    = @('OraUsers')
            LocalGroups = @('Remote Desktop Users', 'Remote Management Users')
        }
    )
    DCIPAddress   = $null        # Will be set during the deployment
}
$vmConfig = [ordered]@{
    DC = [PSCustomObject]@{
        SourceImage  = 'WindowsServer2022'
        VMSize       = 'Standard_B2s_v2'  # Get-AzComputeResourceSku | Where-Object { $_.Locations -contains $location }  https://azureprice.net/
        Script_A     = "$deploymentRoot\Deployment_A.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules      = @(
            'PSFramework'
        )
        FileServer   = [PSCustomObject]@{
            DriveLetter = 'C'
            BaseFolder  = 'FileServer'
            Shares      = @(
                [PSCustomObject]@{
                    Name         = 'Applikationen'
                    Folder       = 'Applikationen'
                    FullAccess   = @("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)")
                    ChangeAccess = @('Everyone')
                }
                [PSCustomObject]@{
                    Name         = 'Software'
                    Folder       = 'Software'
                    FullAccess   = @("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)")
                    ChangeAccess = @('Everyone')
                }
                [PSCustomObject]@{
                    Name         = 'Backup'
                    Folder       = 'Backup'
                    FullAccess   = @("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)")
                    ChangeAccess = @('Everyone')
                }
                [PSCustomObject]@{
                    Name         = 'Temp'
                    Folder       = 'Temp'
                    FullAccess   = @("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)")
                    ChangeAccess = @('Everyone')
                }
            )
            Downloads    = @(
                [PSCustomObject]@{
                    Url    = $Env:MyOracleWindowsDbHomeURL
                    Folder = 'Applikationen\Oracle-Oracle\Software\Oracle_DB_19'
                    File   = 'WINDOWS.X64_193000_db_home.zip'
                }
                [PSCustomObject]@{
                    Url    = $Env:MyOracleWindowsOPatchURL
                    Folder = 'Applikationen\Oracle-Oracle\Software\Oracle_DB_19\Oracle_Opatch_Software'
                    File   = 'p6880880_190000_MSWIN-x86-64.zip'
                }
                [PSCustomObject]@{
                    Url    = $Env:MyOracleWindowsPatch37532350URL
                    Folder = 'Applikationen\Oracle-Oracle\Software\Oracle_DB_19\DB_Patch'
                    File   = 'p37532350_190000_MSWIN-x86-64.zip'
                }
                [PSCustomObject]@{
                    Url    = $Env:MyOracleWindowsSqlDeveloperURL
                    Folder = 'Software\Oracle'
                    File   = 'sqldeveloper-24.3.0.284.2209-x64.zip'
                }
            )
        }
    }
    CLIENT1 = [PSCustomObject]@{
        SourceImage  = 'Windows11'
        VMSize       = 'Standard_B4s_v2'
        Script_A     = "$deploymentRoot\Deployment_A.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules      = @(
            'PSFramework'
        )
    }
<#
    CLIENT2 = [PSCustomObject]@{
        SourceImage  = 'Windows11'
        VMSize       = 'Standard_B4s_v2'
        Script_A     = "$deploymentRoot\Deployment_A.ps1"
        Status       = $statusConfig
        Domain       = $domainConfig
        Packages     = @(
            'notepadplusplus'
            'powershell-core'
        )
        Modules      = @(
            'PSFramework'
        )
    }
#>        
}

# This is a "global" variable, so that it can be used in other commands
$credentials = [ordered]@{
    Admin = [PSCredential]::new("$($domainConfig.NetbiosName)\$($domainConfig.AdminName)", (ConvertTo-SecureString -String $domainConfig.AdminPassword -AsPlainText -Force))
}
foreach ($user in $domainConfig.Users) {
    $credentials[$user.Name] = [PSCredential]::new("$($domainConfig.NetbiosName)\$($user.Name)", (ConvertTo-SecureString -String $user.Password -AsPlainText -Force))
}
