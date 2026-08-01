$ErrorActionPreference = 'Continue'

Import-Module -Name AutomatedLab

$LabName          = 'TestingDbatools'
$LabNetworkBase   = '192.168.3'

$LabAdminUser     = 'Admin'
$LabAdminPassword = 'P@ssw0rd'

$LabDomainName    = 'ordix.local'


try {
    Import-Lab -Name $LabName -NoValidation
    Start-LabVM -ComputerName DC -Wait ; Start-LabVM -All -Wait
    mstsc /v:$LabNetworkBase.20
    break
} catch {
    Write-Host "Lab is not installed, will install now..."
}


<# Some commands that I use for importing, removing, stopping, starting or connecting to the lab:

Import-Lab -Name $LabName -NoValidation
Start-LabVM -ComputerName DC -Wait ; Start-LabVM -All -Wait
mstsc /v:$LabNetworkBase.20

Stop-LabVM -All
Remove-Lab -Name $LabName -Confirm:$false; Get-NetNat -Name $LabName -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false

$ip = "$LabNetworkBase.20"
$user = $LabAdminUser + '@' + $LabDomainName
$pass = $LabAdminPassword
$null = cmdkey /add:TERMSRV/$ip /user:$user /pass:$pass

cmdkey /add:TERMSRV/192.168.3.20 /user:Admin@ordix.local /pass:P@ssw0rd
mstsc /v:192.168.3.20

Enter-LabPSSession -ComputerName ADMIN01




Import-Lab -Name $LabName -NoValidation
Stop-LabVM -ComputerName DC, SQL01, SQL02, SQL03, SQL04, SQL05 -Wait
Start-Sleep -Seconds 10
Get-VMSnapshot -VMName $LabName-DC, $LabName-SQL01, $LabName-SQL02, $LabName-SQL03, $LabName-SQL04, $LabName-SQL05 -Name Level0 | Restore-VMSnapshot -Confirm:$false
Start-LabVM -ComputerName DC -Wait
Start-Sleep -Seconds 60
Start-LabVM -ComputerName SQL01, SQL02, SQL03, SQL04, SQL05 -Wait



#>

function Send-Status {
    Param([string]$Message)
    Add-Content -Path "$PSScriptRoot\status.txt" -Value "$([datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')) - $Message"
    if ($env:MyStatusUrl) {
        $requestParams = @{
            Uri             = $env:MyStatusUrl
            Method          = 'Post'
            ContentType     = 'application/json'
            Body            = @{
                IP      = '127.0.0.1'
                Host    = 'localhost'
                Message = $Message
            } | ConvertTo-Json -Compress
            UseBasicParsing = $true
        }
        try {
            $null = Invoke-WebRequest @requestParams
        } catch {
            Write-Warning -Message "Failed to send status: $_"
        }
    }
}

$LabDnsServer     = '1.1.1.1'

$MachineDefinitionDefaults = @{
    OperatingSystem = 'Windows Server 2025 Standard Evaluation (Desktop Experience)'
    Processors      = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    Memory          = 2GB
    Network         = $LabName
    Gateway         = "$LabNetworkBase.1"
    DomainName      = $LabDomainName
    TimeZone        = 'W. Europe Standard Time'
}

$MachineDefinition = @(
    @{
        Name            = 'DC'
        IpAddress       = "$LabNetworkBase.10"
        DnsServer1      = $LabDnsServer
        Roles           = @(
            'RootDC'
            'CaRoot'
        )
    }
    @{
        Name            = 'ADMIN01'
        IpAddress       = "$LabNetworkBase.20"
        Memory          = 8GB
    }
    @{
        Name            = 'SQL01'
        IpAddress       = "$LabNetworkBase.31"
    }
    @{
        Name            = 'SQL02'
        IpAddress       = "$LabNetworkBase.32"
    }
    @{
        Name            = 'SQL03'
        IpAddress       = "$LabNetworkBase.33"
    }
    @{
        Name            = 'SQL04'
        IpAddress       = "$LabNetworkBase.34"
    }
    @{
        Name            = 'SQL05'
        IpAddress       = "$LabNetworkBase.35"
    }
)


$FileServerFolder = @(
    @{
        Path  = 'FileServer'
        Share = @{
            Name   = 'FileServer'
        }
    }
    @{
        Path  = 'FileServer\Software'
        Share = @{
            Name   = 'Software'
        }
    }
    @{
        Path  = 'FileServer\Software\SQLServer'
    }
    @{
        Path  = 'FileServer\Software\SQLServer\ISO'
    }
    @{
        Path      = 'FileServer\Software\SQLServer\ISO\SQLServer2025'
        ExpandISO = "$labSources\ISOs\SQLServer2025-x64-ENU.iso"
    }
    @{
        Path      = 'FileServer\Software\SQLServer\ISO\SQLServer2022'
        ExpandISO = "$labSources\ISOs\enu_sql_server_2022_developer_edition_x64_dvd_7cacf733.iso"
    }
    @{
        Path      = 'FileServer\Software\SQLServer\ISO\SQLServer2019'
        ExpandISO = "$labSources\ISOs\en_sql_server_2019_developer_x64_dvd_e5ade34a.iso"
    }
    @{
        Path         = 'FileServer\Software\SQLServer\CU'
        DownloadFile = @{
            Name = 'Get-CU.ps1'
            Url  = 'https://raw.githubusercontent.com/andreasjordan/demos/master/dbatools/Get-CU.ps1'
        }
    }
    @{
        Path     = 'FileServer\SampleDatabases'
        DownloadFile = @(
            @{
                Name = 'AdventureWorks2025.bak'
                Url  = 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2025.bak'
            }
            @{
                Name = 'AdventureWorks2022.bak'
                Url  = 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2022.bak'
            }
            @{
                Name = 'AdventureWorks2019.bak'
                Url  = 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2019.bak'
            }
            @{
                Name = 'AdventureWorks2017.bak'
                Url  = 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2017.bak'
            }
        )
        Share = @{
            Name   = 'SampleDatabases'
        }
    }
    @{
        Path  = 'FileServer\Backup'
        Share = @{
            Name   = 'Backup'
        }
    }
    @{
        Path  = 'FileServer\Temp'
        Share = @{
            Name   = 'Temp'
        }
    }
    @{
        Path  = 'FileServer\appveyor-lab'
        Share = @{
            Name   = 'appveyor-lab'
        }
    }
)

$ChocolateyPackages = @(
    'powershell-core'
    'notepadplusplus'
    '7zip'
    'git'
    'vscode'
    'sql-server-management-studio'
    'sqlcmd'
)

$PowerShellModules = @(
    'PSFramework'
    'dbatools'
)



### End of configuration ###

Send-Status -Message "Installing Lab"

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV
Set-LabInstallationCredential -Username $LabAdminUser -Password $LabAdminPassword
Add-LabDomainDefinition -Name $LabDomainName -AdminUser $LabAdminUser -AdminPassword $LabAdminPassword
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace "$LabNetworkBase.0/24"
foreach ($md in $MachineDefinition) {
    # $md = $MachineDefinition[0]
    $lmd = @{ }
    foreach ($key in $MachineDefinitionDefaults.Keys) {
        $lmd.$key = $MachineDefinitionDefaults.$key
    }
    foreach ($key in $md.Keys) {
        $lmd.$key = $md.$key
    }
    $lmd.ResourceName = "$LabName-$($md.Name)"
    Add-LabMachineDefinition @lmd
}
Install-Lab -NoValidation


Send-Status -Message 'Creating NetNat'
$null = New-NetNat -Name $LabName -InternalIPInterfaceAddressPrefix "$LabNetworkBase.0/24"


Send-Status -Message 'Disabling Windows Updates'
Invoke-LabCommand -ComputerName (Get-LabVM) -ActivityName 'Disabling Windows Updates' -ScriptBlock { 
    # https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings
    try {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
        $true
    } catch {
        Write-Warning -Message "Failed to disable Windows Updates: $_"
        $false
    }
}


Send-Status -Message 'Disabling Firewall'
Invoke-LabCommand -ComputerName (Get-LabVM) -ActivityName 'Disabling Firewall' -ScriptBlock { 
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
        $true
    } catch {
        Write-Warning -Message "Failed to disable Firewall: $_"
        $false
    }
}


Send-Status -Message 'Prepare Domain'
Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Domain' -ArgumentList $LabAdminPassword -ScriptBlock {
    param ($Password)

    try {
        if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory}
        Start-Transcript -Path C:\Temp\PrepareDomain.log

        Import-Module -Name KDS
        Import-Module -Name ActiveDirectory
        Import-Module -Name GroupPolicy

        $adminComputerOU = New-ADOrganizationalUnit -Name AdminComputer -ProtectedFromAccidentalDeletion:$false -PassThru
        $adminUserOU = New-ADOrganizationalUnit -Name AdminUser -ProtectedFromAccidentalDeletion:$false -PassThru
        $sqlComputerOU = New-ADOrganizationalUnit -Name SqlComputer -ProtectedFromAccidentalDeletion:$false -PassThru
        $sqlUserOU = New-ADOrganizationalUnit -Name SqlUser -ProtectedFromAccidentalDeletion:$false -PassThru

        Get-ADComputer -Filter 'Name -like "ADMIN*"' | Move-ADObject -TargetPath $adminComputerOU.DistinguishedName
        Get-ADComputer -Filter 'Name -like "SQL*"' | Move-ADObject -TargetPath $sqlComputerOU.DistinguishedName

        $accountPassword = (ConvertTo-SecureString -String $Password -AsPlainText -Force)
        New-ADUser -Name SQLAdmin -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLUser1 -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLUser2 -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLUser3 -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLUser4 -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLUser5 -AccountPassword $accountPassword -Enabled $true -Path $sqlUserOU.DistinguishedName

        New-ADGroup -Name SQLAdmins -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName
        New-ADGroup -Name SQLUsers -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName

        Add-ADGroupMember -Identity SQLAdmins -Members SQLAdmin
        Add-ADGroupMember -Identity SQLUsers -Members SQLUser1, SQLUser2, SQLUser3, SQLUser4, SQLUser5

        # Setup of gMSA for SQL Server

        if (-not (Get-KdsRootKey)) {
            $null = Add-KdsRootKey -EffectiveTime ([datetime]::Now).AddHours(-10)
        }

        $serviceAccountName        = 'gMSA-SQLServer'
        $serviceAccountDescription = 'Group-managed service account for SQL Server'

        $computerName              = (Get-ADComputer -Filter 'Name -like "SQL*"').Name
        $computerAccountName       = $computerName | ForEach-Object { $_ + '$' }
        $serviceAccountDNSHostName = "$serviceAccountName.$((Get-ADDomain).DNSRoot)"

        $adServiceAccountParams = @{
            Path                                       = $sqlUserOU.DistinguishedName
            Name                                       = $serviceAccountName
            Description                                = $serviceAccountDescription
            DNSHostName                                = $serviceAccountDNSHostName
            PrincipalsAllowedToRetrieveManagedPassword = $computerAccountName
            Enabled                                    = $true
        }

        $serviceAcccount = New-ADServiceAccount @adServiceAccountParams -PassThru
        $null = dsacls $serviceAcccount.DistinguishedName /G "SELF:RPWP;servicePrincipalName"

        New-ADGroup -Name SQLServiceAccounts -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName
        Add-ADGroupMember -Identity SQLServiceAccounts -Members (Get-ADServiceAccount -Identity $serviceAccountName)

        Stop-Transcript
        $true
    } catch {
        Write-Warning -Message "Failed to prepare domain: $_"
        $false
    }
}


Send-Status -Message 'Prepare Fileserver'
foreach ($folder in $FileServerFolder) {
    # $folder = $fileServerConfig.Folder[0]

    Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ArgumentList "C:\$($folder.Path)" -ScriptBlock { 
        param($Path) 
        try {
            $null = New-Item -Path $Path -ItemType Directory
            $true
        } catch {
            Write-Warning -Message "Failed to create directory: $_"
            $false
        }
    }

    if ($folder.ExpandISO) {
        $isoImage = Mount-LabIsoImage -ComputerName DC -IsoPath $folder.ExpandISO -PassThru
        Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ArgumentList "C:\$($folder.Path)", $isoImage.DriveLetter -ScriptBlock { 
            param($Path, $DriveLetter) 
            try {
                $null = New-Item -Path $Path -ItemType Directory -Force
                Copy-Item -Path "$DriveLetter\*" -Destination $Path -Recurse 
                $true
            } catch {
                Write-Warning -Message "Failed to expand ISO: $_"
                $false
            }
        }
        Dismount-LabIsoImage -ComputerName DC 
    }

    foreach ($file in $folder.DownloadFile) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ArgumentList $file.Url, "C:\$($folder.Path)\$($file.Name)" -ScriptBlock { 
            param($Uri, $OutFile)
            try {
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing 
                $true
            } catch {
                Write-Warning -Message "Failed to download file: $_"
                $false
            }
        }
    }

    foreach ($file in $folder.CopyFile) {
        Copy-LabFileItem -ComputerName DC -Path $file -DestinationFolderPath "C:\$($folder.Path)"
    }

    if ($folder.CopyFolder) {
        Copy-LabFileItem -ComputerName DC -Path "$($folder.CopyFolder)\*" -DestinationFolderPath "C:\$($folder.Path)" -Recurse
    }

    if ($folder.Access) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ArgumentList $folder.Path, $folder.Access -ScriptBlock { 
            param($Path, $Access)
            try {
                foreach ($acc in $Access) {
                    $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        "$domainName\$($acc.AccountName)",
                        $acc.AccessRight,
                        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        'Allow'
                    )
                    $acl = Get-Acl -Path "C:\$Path"
                    $acl.SetAccessRule($accessRule)
                    Set-Acl -Path "C:\$Path" -AclObject $acl
                }
                $true
            } catch {
                Write-Warning -Message "Failed to set access rights: $_"
                $false
            }
        }
    }

    if ($folder.Share) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ArgumentList $folder.Path, $folder.Share -ScriptBlock { 
            param($Path, $Share)
            try {
                $domainName = (Get-ADDomain).NetBIOSName
                $null = New-SmbShare -Path "C:\$Path" -Name $Share.Name
                foreach ($access in $Share.Access) {
                    $null = Grant-SmbShareAccess -Name $Share.Name -AccountName "$domainName\$($access.AccountName)" -AccessRight $access.AccessRight -Force
                }
                if (-not $Share.Access) {
                    $null = Grant-SmbShareAccess -Name $Share.Name -AccountName 'Everyone' -AccessRight Full -Force
                }
                $true
            } catch {
                Write-Warning -Message "Failed to create SMB share: $_"
                $false
            }
        }
    }
}

Invoke-LabCommand -ComputerName DC -ActivityName 'Prepare Fileserver' -ScriptBlock {
    try {
        $dnsRoot = (Get-ADDomain).DNSRoot
        Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $dnsRoot -HostNameAlias dc.$dnsRoot -Name fs
        $true
    } catch {
        Write-Warning -Message "Failed to create DNS CNAME record: $_"
        $false
    }
}


Send-Status -Message 'Installing RSAT'
Install-LabWindowsFeature -ComputerName ADMIN01 -FeatureName RSAT-Clustering, RSAT-AD-Tools -IncludeAllSubFeature
Restart-LabVM -ComputerName ADMIN01 -Wait
Start-Sleep -Seconds 30


Send-Status -Message 'Installing Chocolatey Packages'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing Chocolatey Packages' -ArgumentList @(, $ChocolateyPackages) -ScriptBlock { 
    param($ChocolateyPackages)

    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory}
    $logPath = 'C:\Temp\InstallChocolateyPackages.log'

    try {
        Invoke-Expression -Command ([System.Net.WebClient]::new().DownloadString('https://chocolatey.org/install.ps1')) *>$logPath
        $installResult = choco install $ChocolateyPackages --confirm --limitoutput --no-progress *>&1
        if ($installResult -match 'Warnings:') {
            Write-Warning -Message 'Chocolatey generated warnings'
        }
        $info = $installResult -match 'Chocolatey installed (\d+)/(\d+) packages' | Select-Object -First 1
        if ($info -match 'Chocolatey installed (\d+)/(\d+) packages') {
            if ($Matches[1] -ne $Matches[2]) {
                Write-Warning -Message "Chocolatey only installed $($Matches[1]) of $($Matches[2]) packages"
                $installResult | Add-Content -Path $logPath
            }
        } else {
            Write-Warning -Message "InstallResult: $installResult"
        }
        $true
    } catch {
        $message = "Setting up Chocolatey failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
        $false
    }
}


Send-Status -Message 'Installing PowerShell modules'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing PowerShell modules' -ArgumentList @(, $PowerShellModules) -ScriptBlock { 
    param($PowerShellModules)

    if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory}
    $logPath = 'C:\Temp\InstallPowerShellModules.log'

    $ErrorActionPreference = 'Stop'

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ((Get-PackageProvider -ListAvailable).Name -notcontains 'Nuget') {
            $null = Install-PackageProvider -Name Nuget -Force
            'Install-PackageProvider ok' | Add-Content -Path $logPath
        } else {
            'Install-PackageProvider not needed' | Add-Content -Path $logPath
        }
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            'Set-PSRepository ok' | Add-Content -Path $logPath
        } else {
            'Set-PSRepository not needed' | Add-Content -Path $logPath
        }
        foreach ($name in $PowerShellModules) {
            if (-not (Get-Module -Name $name -ListAvailable)) {
                Install-Module -Name $name
                "Install-Module $name ok" | Add-Content -Path $logPath
            } else {
                "Install-Module $name not needed" | Add-Content -Path $logPath
            }
        }

        Install-Module -Name Pester -RequiredVersion 6.0.0 -Force -SkipPublisherCheck
        Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.18.2 -Force -SkipPublisherCheck

        # Configure dbatools to suppress the message during import and to accept self-signed certificates:
        Import-Module -Name dbatools *> $null
        Set-DbatoolsConfig -FullName Import.EncryptionMessageCheck -Value $false -Register
        Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -Register
        $true
    } catch {
        $message = "Setting up PowerShell failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
        $false
    }
}


Send-Status -Message 'Downloading SQL Server CUs'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Downloading SQL Server CUs' -ScriptBlock { 
    if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory}
    $logPath = 'C:\Temp\DownloadCUs.log'

    $ErrorActionPreference = 'Stop'

    try {
        Set-Location -Path \\fs\Software\SQLServer\CU
        .\Get-CU.ps1
        $true
    } catch {
        $message = "Downloading SQL Server CUs failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
        $false
    }
}


Send-Status -Message 'Setting up CredSSP'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting up CredSSP' -ScriptBlock { 
    if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory }
    $logPath = 'C:\Temp\SetupCredSSP.log'

    $ErrorActionPreference = 'Stop'

    try {
        Get-ADComputer -Filter 'Name -like "SQL*"' |
            ForEach-Object -Process { 
                $null = Enable-WSManCredSSP -Role Client -DelegateComputer $_.Name -Force
                $null = Enable-WSManCredSSP -Role Client -DelegateComputer $_.DNSHostName -Force
                Invoke-Command -ComputerName $_.Name -ScriptBlock { $null = Enable-WSManCredSSP -Role Server -Force }
            }
        $true
    } catch {
        $message = "Setting up CredSSP failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
        $false
    }
}


Send-Status -Message 'Downloading repositories'
Get-PSSession | Remove-PSSession
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Downloading repositories' -ScriptBlock { 
    if (-not (Test-Path -Path 'C:\Temp')) { $null = New-Item -Path 'C:\Temp' -ItemType Directory }
    $logPath = 'C:\Temp\DownloadDemos.log'

    $ErrorActionPreference = 'Stop'

    try {
        $null = New-Item -Path C:\GitHub -ItemType Directory

        Set-Location -Path C:\GitHub
        git clone --quiet https://github.com/dataplat/dbatools.git
        git clone --quiet https://github.com/dataplat/appveyor-lab.git
        git clone --quiet https://github.com/andreasjordan/testing-dbatools.git
        git clone --quiet https://github.com/andreasjordan/demos.git
        Copy-Item -Path C:\GitHub\appveyor-lab\* -Destination \\fs\appveyor-lab -Recurse
        $true
    } catch {
        $message = "Downloading demo repository failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
        $false
    }
}


Send-Status -Message 'Enabling german keyboard'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Enabling german keyboard' -ScriptBlock { 
    try {
        Set-WinUserLanguageList -LanguageList @('de-DE','en-US') -Force -WarningAction SilentlyContinue
        $true
    } catch {
        Write-Warning -Message "Failed to set language list: $_"
        $false
    }
}
# The default language is still not the first one in the list. To change the keyboard layout use "LeftAlt+Shift". 


Send-Status -Message 'Disabling hardware acceleration'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Disabling hardware acceleration' -ScriptBlock { 
    try {
        reg add "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v DisableHardwareAcceleration /t REG_DWORD /d 1 /f
        $true
    } catch {
        Write-Warning -Message "Failed to disable hardware acceleration: $_"
        $false
    }
    
}


if ($env:MyStatusURL) {
    Send-Status -Message 'Setting environment variable MyStatusURL'
    Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting environment variable MyStatusURL' -ArgumentList $env:MyStatusURL -ScriptBlock { 
        try {
            [Environment]::SetEnvironmentVariable('MyStatusURL', $args[0], 'Machine')
            $true
        } catch {
            Write-Warning -Message "Failed to set environment variable MyStatusURL: $_"
            $false
        }
    }
}


Send-Status -Message 'Setting environment variable MyConfigFilename'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting environment variable MyConfigFilename' -ArgumentList 'TestConfig_remote_instances.ps1' -ScriptBlock { 
     [Environment]::SetEnvironmentVariable('MyConfigFilename', $args[0], 'Machine')
     $true
}


Get-PSSession | Remove-PSSession

<#
Send-Status -Message "Creating Snapshot"
Stop-LabVM -All
Start-Sleep -Seconds 10
Checkpoint-VM -Name $LabName-* -SnapshotName Level0
Start-LabVM -ComputerName DC -Wait ; Start-LabVM -All
Start-Sleep -Seconds 30

#>

cmdkey /add:TERMSRV/192.168.3.20 /user:Admin@ordix.local /pass:P@ssw0rd
mstsc /v:192.168.3.20


break

Send-Status -Message 'Installing instances'
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing instances' -ScriptBlock { 
    try {
        C:\GitHub\testing-dbatools\01_install_windows_cluster01.ps1
        C:\GitHub\testing-dbatools\02_install_windows_cluster02.ps1
        C:\GitHub\testing-dbatools\03_install_alwayson_fci.ps1
        C:\GitHub\testing-dbatools\04_install_alwayson_fci2.ps1
        C:\GitHub\testing-dbatools\05_install_remote_instances.ps1
        C:\GitHub\testing-dbatools\06_configuring_instances.ps1
        $true
    } catch {
        Write-Warning -Message "Failed to install instances: $_"
        $false
    }
}




Enter-LabPSSession -ComputerName ADMIN01

Restart-LabVM -ComputerName ADMIN01 -Wait

try {
    Send-Status -Message 'Starting to remove startup task'

    Unregister-ScheduledTask -TaskName DeploymentAtStartup -Confirm:$false

    Send-Status -Message 'Finished to remove startup task'
} catch {
    Send-Status -Message "Failed to remove startup task: $_"
    return
}

Send-Status -Message "Finished"
