$ErrorActionPreference = 'Stop'

Start-Transcript -Path "$PSScriptRoot\transcript-$([datetime]::Now.ToString('yyyy-MM-dd-HH-mm-ss')).txt"

$config = Get-Content -Path $PSScriptRoot\config.txt | ConvertFrom-Json

function Send-Status {
    Param([string]$Message)
    $requestParams = @{
        Uri             = $config.Status.Uri
        Method          = 'Post'
        ContentType     = 'application/json'
        Body            = @{
            IP      = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp).IPAddress
            Host    = $env:COMPUTERNAME
            Message = $Message
        } | ConvertTo-Json -Compress
        UseBasicParsing = $true
    }
    try {
        $null = Invoke-WebRequest @requestParams
        Add-Content -Path $PSScriptRoot\status.txt -Value "[$([datetime]::Now.ToString('HH:mm:ss'))] $Message"
    } catch {
        Add-Content -Path $PSScriptRoot\status.txt -Value "[$([datetime]::Now.ToString('HH:mm:ss'))] Failed to send status [$Message]: $_"
    }
}

if (-not (Get-Command -Name choco -ErrorAction SilentlyContinue)) {
    try {
        Send-Status -Message 'Starting to install chocolatey'

        $null = Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

        Send-Status -Message 'Finished to install chocolatey'
        Restart-Computer -Force
        return
    } catch {
        if ($_ -match 'a reboot is required') {
            Send-Status -Message "Rebooting to install chocolatey because: $_"
            Restart-Computer -Force
            return
        }
        Send-Status -Message "Failed to install chocolatey: $_"
        return
    }
}

$installedPackages = choco list | Select-Object -Skip 1 | Select-Object -SkipLast 1 | ForEach-Object -Process { $_.split(' ')[0] }
$rebootNeeded = $false
foreach ($package in $config.Packages) {
    if ($installedPackages -notcontains $package) {
        try {
            Send-Status -Message "Starting to install chocolatey package $package"
    
            $installResult = choco install $package --confirm --limitoutput --no-progress
            if ($installResult -match 'Warnings:') {
                Send-Status -Message 'Chocolatey generated warnings'
            }
            $info = $installResult -match 'Chocolatey installed (\d+)/(\d+) packages' | Select-Object -First 1
            if ($info -match 'Chocolatey installed (\d+)/(\d+) packages') {
                if ($Matches[1] -ne $Matches[2]) {
                    Send-Status -Message "Chocolatey only installed $($Matches[1]) of $($Matches[2]) packages"
                    $installResult | Add-Content -Path $PSScriptRoot\Chocolatey.txt
                }
            } else {
                Send-Status -Message "Failed to install chocolatey package $package"
                $installResult | Add-Content -Path $PSScriptRoot\Chocolatey.txt
                return
            }

            if ($package -eq 'sql-server-management-studio') {
                Copy-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft SQL Server Tools*\SQL Server Management Studio*.lnk' -Destination C:\Users\Public\Desktop
            }

            if ($package -eq 'sql-server-management-studio', 'git') {
                $rebootNeeded = $true
            }

            Send-Status -Message "Finished to install chocolatey package $package"
        } catch {
            Send-Status -Message "Failed to install chocolatey package $package"
            return
        }
    }
}
if ($rebootNeeded) {
    Restart-Computer -Force
    return
}

if ((Get-PackageProvider).Name -notcontains 'NuGet') {
    try {
        Send-Status -Message 'Starting to setup NuGet for PowerShell'

        $null = Install-PackageProvider -Name Nuget -Force

        Send-Status -Message 'Finished to setup NuGet for PowerShell'
    } catch {
        Send-Status -Message "Failed to setup NuGet for PowerShell: $_"
        return
    }
}

if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
    try {
        Send-Status -Message 'Starting to setup PSGallery as trusted'

        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

        Send-Status -Message 'Finished to setup PSGallery as trusted'
    } catch {
        Send-Status -Message "Failed to setup PSGallery as trusted: $_"
        return
    }
}

$installedModules = (Get-Module -ListAvailable).Name 
foreach ($module in $config.Modules) {
    if ($installedModules -notcontains $module) {
        try {
            Send-Status -Message "Starting to install PowerShell module $module"
    
            Install-Module -Name $module

            if ($module -eq 'dbatools') {
                Import-Module -Name dbatools
                Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -PassThru | Register-DbatoolsConfig -Scope SystemDefault
            }
    
            Send-Status -Message "Finished to install PowerShell module $module"
        } catch {
            Send-Status -Message "Failed to install PowerShell module $module"
            return
        }
    }
}

if ($env:COMPUTERNAME -eq 'DC' -and (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ne 5) {
    try {
        Send-Status -Message 'Starting to promote computer to a domain controller'

        $adminPassword = ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force

        $null = Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

        $addsForestParams = @{
            DomainName                    = $config.Domain.Name
            DomainNetbiosName             = $config.Domain.NetbiosName
            SafeModeAdministratorPassword = $adminPassword
            DomainMode                    = 'def'
            ForestMode                    = 'WinThreshold'
            InstallDns                    = $true
            SysvolPath                    = 'C:\Windows\Sysvol'
            DatabasePath                  = 'C:\Windows\NTDS'
            LogPath                       = 'C:\Windows\NTDS'
            Force                         = $true
            NoRebootOnCompletion          = $true
            WarningAction                 = 'SilentlyContinue'
        }
        $null = Install-ADDSForest @addsForestParams

        Send-Status -Message 'Finished to promote computer to a domain controller'
        Restart-Computer -Force
        return
    } catch {
        Send-Status -Message "Failed to promote computer to a domain controller: $_"
        return
    }
}

if ($env:COMPUTERNAME -ne 'DC' -and (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ne 3) {
    try {
        Send-Status -Message 'Starting to join the computer to the domain'

        $adminAccountName = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
        $adminPassword = ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force

        Set-DnsClientServerAddress -InterfaceIndex ((Get-NetIPConfiguration).InterfaceIndex) -ServerAddresses $config.Domain.DCIPAddress

        $addComputerParams = @{
            DomainName = $config.Domain.Name
            Server     = "dc.$($config.Domain.Name)"
            Credential = [PSCredential]::new($adminAccountName, $adminPassword)
        }
        while ( $true ) {
            try {
                Add-Computer @addComputerParams
                break
            } catch {
                Start-Sleep -Seconds 60
            }
        }

        Send-Status -Message 'Finished to join the computer to the domain'
        Restart-Computer -Force
        return
    } catch {
        Send-Status -Message "Failed to join the computer to the domain: $_"
        return
    }
}

if ($env:COMPUTERNAME -eq 'DC') {
    Send-Status -Message 'Waiting for domain to be ready'
    while ( $true ) { 
        try {
            $null = Get-ADUser -Filter *
            break
        } catch {
            Start-Sleep -Seconds 30
        }
    }

    if ((Get-ADUser -Filter *).Name -notcontains $config.Domain.AdminName) {
        try {
            Send-Status -Message 'Starting to create admin'
    
            $adminPassword = ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force
            New-ADUser -Name $config.Domain.AdminName -AccountPassword $adminPassword -Enabled $true
            Add-ADGroupMember -Identity 'Domain Admins' -Members Admin
            
            Send-Status -Message 'Finished to create admin'
        } catch {
            Send-Status -Message "Failed to create admin: $_"
            return
        }
    }

    if ((Get-ADUser -Filter *).Name -notcontains $config.Domain.UserName) {
        try {
            Send-Status -Message 'Starting to create user'
    
            $userPassword = ConvertTo-SecureString -String $config.Domain.UserPassword -AsPlainText -Force
            New-ADUser -Name $config.Domain.UserName -AccountPassword $userPassword -Enabled $true
            
            Send-Status -Message 'Finished to create user'
        } catch {
            Send-Status -Message "Failed to create user: $_"
            return
        }
    }

    if ((Get-PSDrive -PSProvider FileSystem).Name -notcontains $config.FileServerDriveLetter) {
        try {
            Send-Status -Message 'Starting to create file server drive'
    
            $disk = Get-Disk | Where-Object -Property PartitionStyle -EQ 'RAW' | Sort-Object -Property Number | Select-Object -First 1
            $disk | Initialize-Disk -PartitionStyle GPT
            $partition = $disk | New-Partition -UseMaximumSize -DriveLetter $config.FileServerDriveLetter
            $null = $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "FileServer"
    
            Send-Status -Message 'Finished to create file server drive'
        } catch {
            Send-Status -Message "Failed to create file server drive: $_"
            return
        }
    }
    
    if (-not (Test-Path -Path "$($config.FileServerDriveLetter):\FileServer")) {
        try {
            Send-Status -Message 'Starting to create file server'
    
            $adminAccountName = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
    
            $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer" -ItemType Directory
            $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer" -Name FileServer
            $null = Grant-SmbShareAccess -Name FileServer -AccountName $adminAccountName -AccessRight Full -Force
        
            $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software" -ItemType Directory
            $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer\Software" -Name Software
            $null = Grant-SmbShareAccess -Name Software -AccountName $adminAccountName -AccessRight Full -Force
    
            Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $config.Domain.Name -HostNameAlias "dc.$($config.Domain.Name)" -Name fs
            
            Send-Status -Message 'Finished to create file server'
        } catch {
            Send-Status -Message "Failed to create file server: $_"
            return
        }
    }
}



try {
    Send-Status -Message 'Starting to disable server manager'

    $null = Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask

    Send-Status -Message 'Finished to disable server manager'
} catch {
    Send-Status -Message "Failed to disable server manager: $_"
    return
}

try {
    Send-Status -Message 'Starting to set time zone'

    Set-Timezone -Id "W. Europe Standard Time"

    Send-Status -Message 'Finished to set time zone'
} catch {
    Send-Status -Message "Failed to set time zone: $_"
    return
}

try {
    Send-Status -Message 'Starting to configure edge browser'

    $null = New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge
    $null = New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name HideFirstRunExperience -PropertyType DWord -Value 1
    $null = New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name EditFavoritesEnabled -PropertyType DWord -Value 0
    $null = New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name NewTabPageLocation -PropertyType String -Value 'https://seminare.ordix.de'
    Copy-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk' -Destination C:\Users\Public\Desktop
    
    Send-Status -Message 'Finished to configure edge browser'
} catch {
    Send-Status -Message "Failed to configure edge browser: $_"
    return
}



try {
    Send-Status -Message 'Starting to remove startup task'

    Unregister-ScheduledTask -TaskName DeploymentAtStartup -Confirm:$false

    Send-Status -Message 'Finished to remove startup task'
} catch {
    Send-Status -Message "Failed to remove startup task: $_"
    return
}

Send-Status -Message 'Finished deployment'
