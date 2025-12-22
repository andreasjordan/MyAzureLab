$ErrorActionPreference = 'Continue'

Import-Module -Name AutomatedLab

$LabName          = 'TestingDbatools'
$LabNetworkBase   = '192.168.3'

$LabAdminUser     = 'Admin'
$LabAdminPassword = 'P@ssw0rd'

$LabDomainName    = 'ordix.local'


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

#>


function Send-Status {
    Param([string]$Message)
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
        Roles           = 'RootDC'
    }
    @{
        Name            = 'ADMIN01'
        IpAddress       = "$LabNetworkBase.20"
        Memory          = 4GB
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

$null = New-NetNat -Name $LabName -InternalIPInterfaceAddressPrefix "$LabNetworkBase.0/24"

Invoke-LabCommand -ComputerName (Get-LabVM) -ActivityName 'Disable Windows updates' -ScriptBlock { 
    # https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
}




# Configure the AD
Send-Status -Message "Configure the AD"
Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareDomain' -ArgumentList $LabAdminPassword -ScriptBlock {
    param ($Password)

    Start-Transcript -Path C:\DeployDebug\PrepareDomain.log

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


    # Begin setup of gMSA for SQL Server

    if (-not (Get-KdsRootKey)) {
        $null = Add-KdsRootKey -EffectiveTime ([datetime]::Now).AddHours(-10)
    }

    $serviceAccountName        = 'gMSA-SQLServer'
    $serviceAccountDescription = 'Group-managed service account for SQL Server'

    $computerName              = (Get-ADComputer -Filter 'Name -like "SQL*"').Name
    $computerAccountName       = $computerName | ForEach-Object { $_ + '$' }
    $serviceAccountDNSHostName = "$serviceAccountName.$((Get-ADDomain).DNSRoot)"
    $serviceAccountUsername    = "$((Get-ADDomain).NetBIOSName.ToUpper())\$serviceAccountName" + '$'

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

    Restart-Computer -ComputerName $computerName -Force

    # End setup of gMSA for SQL Server

    Stop-Transcript
}


Send-Status -Message "PrepareFileserver"
foreach ($folder in $FileServerFolder) {
    # $folder = $fileServerConfig.Folder[0]

    Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ArgumentList "C:\$($folder.Path)" -ScriptBlock { param($Path) $null = New-Item -Path $Path -ItemType Directory }

    if ($folder.ExpandISO) {
        $isoImage = Mount-LabIsoImage -ComputerName DC -IsoPath $folder.ExpandISO -PassThru
        Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ArgumentList "C:\$($folder.Path)", $isoImage.DriveLetter -ScriptBlock { param($Path, $DriveLetter) $null = New-Item -Path $Path -ItemType Directory -Force ; Copy-Item -Path "$DriveLetter\*" -Destination $Path -Recurse }
        Dismount-LabIsoImage -ComputerName DC 
    }

    foreach ($file in $folder.DownloadFile) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ArgumentList $file.Url, "C:\$($folder.Path)\$($file.Name)" -ScriptBlock { param($Uri, $OutFile) Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing }
    }

    foreach ($file in $folder.CopyFile) {
        Copy-LabFileItem -ComputerName DC -Path $file -DestinationFolderPath "C:\$($folder.Path)"
    }

    if ($folder.CopyFolder) {
        Copy-LabFileItem -ComputerName DC -Path "$($folder.CopyFolder)\*" -DestinationFolderPath "C:\$($folder.Path)" -Recurse
    }

    if ($folder.Access) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ArgumentList $folder.Path, $folder.Access -ScriptBlock { 
            param($Path, $Access)
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
        }
    }

    if ($folder.Share) {
        Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ArgumentList $folder.Path, $folder.Share -ScriptBlock { 
            param($Path, $Share)
            $domainName = (Get-ADDomain).NetBIOSName
            $null = New-SmbShare -Path "C:\$Path" -Name $Share.Name
            foreach ($access in $Share.Access) {
                $null = Grant-SmbShareAccess -Name $Share.Name -AccountName "$domainName\$($access.AccountName)" -AccessRight $access.AccessRight -Force
            }
            if (-not $Share.Access) {
                $null = Grant-SmbShareAccess -Name $Share.Name -AccountName 'Everyone' -AccessRight Full -Force
            }
        }
    }
}

Invoke-LabCommand -ComputerName DC -ActivityName 'PrepareFileserver' -ScriptBlock {
    $dnsRoot = (Get-ADDomain).DNSRoot
    Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $dnsRoot -HostNameAlias dc.$dnsRoot -Name fs
}

Send-Status -Message "Install RSAT"
Install-LabWindowsFeature -ComputerName ADMIN01 -FeatureName RSAT-Clustering, RSAT-AD-Tools -IncludeAllSubFeature
Restart-LabVM -ComputerName ADMIN01 -Wait
Start-Sleep -Seconds 30


$pingSucceeded = Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Testing internet access' -PassThru -ScriptBlock { 
    (Test-NetConnection -ComputerName www.google.de -WarningAction SilentlyContinue).PingSucceeded
}

if (-not $pingSucceeded) {
    Write-Warning -Message "We don't have internet access, but let's wait for 30 seconds and try again"
    Start-Sleep -Seconds 30
    $pingSucceeded = Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Testing internet access' -PassThru -ScriptBlock { 
        (Test-NetConnection -ComputerName www.google.de -WarningAction SilentlyContinue).PingSucceeded
    }
    if (-not $pingSucceeded) {
        Write-Warning -Message "We don't have internet access, so stopping here"
        break
    }
}

Send-Status -Message "Installing chocolatey packages"
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing chocolatey packages' -ArgumentList @(, $ChocolateyPackages) -ScriptBlock { 
    param($ChocolateyPackages)

    $ErrorActionPreference = 'Stop'

    $logPath = 'C:\DeployDebug\InstallChocolateyPackages.log'

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
    } catch {
        $message = "Setting up Chocolatey failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
    }
}

Send-Status -Message "Installing PowerShell modules"
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing PowerShell modules' -ArgumentList @(, $PowerShellModules) -ScriptBlock { 
    param($PowerShellModules)

    $logPath = 'C:\DeployDebug\InstallPowerShellModules.log'

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

        Install-Module -Name Pester -Force -SkipPublisherCheck
        Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck -MaximumVersion 1.18.2

        # Configure dbatools to suppress the message during import and to accept self-signed certificates:
        Import-Module -Name dbatools *> $null
        Set-DbatoolsConfig -FullName Import.EncryptionMessageCheck -Value $false -Register
        Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -Register
    } catch {
        $message = "Setting up PowerShell failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
    }
}

Send-Status -Message "Downloading SQL Server CUs"
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Downloading SQL Server CUs' -ScriptBlock { 
    $logPath = 'C:\DeployDebug\DownloadCUs.log'

    $ErrorActionPreference = 'Stop'

    try {
        Set-Location -Path \\fs\Software\SQLServer\CU
        .\Get-CU.ps1
    } catch {
        $message = "Downloading SQL Server CUs failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
    }
}

Send-Status -Message "Setting up CredSSP"
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting up CredSSP' -ScriptBlock { 
    $logPath = 'C:\DeployDebug\SetupCredSSP.log'

    $ErrorActionPreference = 'Stop'

    try {
        Get-ADComputer -Filter 'Name -like "SQL*"' |
            ForEach-Object -Process { 
                $null = Enable-WSManCredSSP -Role Client -DelegateComputer $_.Name -Force
                $null = Enable-WSManCredSSP -Role Client -DelegateComputer $_.DNSHostName -Force
            }
    } catch {
        $message = "Setting up CredSSP failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
    }
}

Send-Status -Message "Downloading repositories"
Get-PSSession | Remove-PSSession
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Downloading repositories' -ScriptBlock { 
    $logPath = 'C:\DeployDebug\DownloadDemos.log'

    $ErrorActionPreference = 'Stop'

    try {
        $null = New-Item -Path C:\GitHub -ItemType Directory

        Set-Location -Path C:\GitHub
        git clone --quiet https://github.com/dataplat/dbatools.git
        git clone --quiet https://github.com/dataplat/appveyor-lab.git
        git clone --quiet https://github.com/andreasjordan/testing-dbatools.git
        git clone --quiet https://github.com/andreasjordan/demos.git
        Copy-Item -Path C:\GitHub\appveyor-lab\* -Destination \\fs\appveyor-lab -Recurse
    } catch {
        $message = "Downloading demo repository failed: $_"
        $message | Add-Content -Path $logPath
        Write-Warning -Message $message
    }
}

Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Enabling german keyboard' -ScriptBlock { 
    Set-WinUserLanguageList -LanguageList @('en-US','de-DE') -Force
}

Invoke-LabCommand -ComputerName SQL01, SQL02, SQL03 -ActivityName 'Downloading repositories' -ScriptBlock { 
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
}

Get-PSSession | Remove-PSSession

Send-Status -Message "Installing instances"
Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Installing instances' -ScriptBlock { 
    C:\GitHub\testing-dbatools\install_remote_instances.ps1
}



if ($env:MyStatusURL) {
    Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting environment variable MyStatusURL' -ArgumentList $env:MyStatusURL -ScriptBlock { 
         [Environment]::SetEnvironmentVariable('MyStatusURL', $args[0], 'Machine')
    }
}

Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Setting environment variable MyConfigFilename' -ArgumentList 'TestConfig_remote_instances.ps1' -ScriptBlock { 
     [Environment]::SetEnvironmentVariable('MyConfigFilename', $args[0], 'Machine')
}

Restart-LabVM -ComputerName ADMIN01 -Wait

$ip = "$LabNetworkBase.20"
$user = $LabAdminUser + '@' + $LabDomainName
$pass = $LabAdminPassword
$null = cmdkey /add:TERMSRV/$ip /user:$user /pass:$pass

mstsc /v:$LabNetworkBase.20

Send-Status -Message "Finished"
