$ErrorActionPreference = 'Stop'

Start-Transcript -Path "$PSScriptRoot\transcript-$([datetime]::Now.ToString('yyyy-MM-dd-HH-mm-ss')).txt"

$config = Get-Content -Path $PSScriptRoot\config.txt | ConvertFrom-Json

$statusUri = $config.Status.Uri
$statusIP = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp).IPAddress
$statusHost = hostname

function Send-Status {
    Param([string]$Message)
    Add-Content -Path $PSScriptRoot\status.txt -Value "[$([datetime]::Now.ToString('HH:mm:ss'))] $Message"
    if ($statusUri) {
        $requestParams = @{
            Uri             = $statusUri
            Method          = 'Post'
            ContentType     = 'application/json'
            Body            = @{
                IP      = $statusIP
                Host    = $statusHost
                Message = $Message
            } | ConvertTo-Json -Compress
            UseBasicParsing = $true
        }
        try {
            $null = Invoke-WebRequest @requestParams
        } catch {
            # Ignore errors
        }
    }
}

Send-Status -Message 'Starting deployment'

if ((Get-WSManCredSSP)[1] -match 'This computer is not configured to receive credentials') {
    try {
        Send-Status -Message 'Starting to setup CredSSP'

        $null = Enable-WSManCredSSP -Role Server -Force

        Send-Status -Message 'Finished to setup CredSSP'
    } catch {
        Send-Status -Message "Failed to setup CredSSP: $_"
        return
    }
}

if ($config.DelegateComputer -and (Get-WSManCredSSP)[0] -match 'The machine is not configured to allow delegating fresh credentials') {
    foreach ($computer in $config.DelegateComputer) {
        $null = Enable-WSManCredSSP -Role Client -DelegateComputer "$computer.$($config.Domain.Name)", $computer -Force
    }
}

if (-not (Get-ChildItem -Path WSMan:\localhost\Listener\ | Where-Object { $_.Keys -contains 'Transport=HTTP' })) {
    try {
        Send-Status -Message 'Starting to setup HTTP listener for winrm'

        $null = 'y' | winrm quickconfig

        Send-Status -Message 'Finished to setup HTTP listener for winrm'
    } catch {
        Send-Status -Message "Failed to setup HTTP listener for winrm: $_"
        return
    }
}

if ((Get-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)').Enabled -contains 'False') {
    try {
        Send-Status -Message 'Starting to configure firewall for WMI'

        Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)'
        
        Send-Status -Message 'Finished to configure firewall for WMI'
    } catch {
        Send-Status -Message "Failed to configure firewall for WMI: $_"
        return
    }
}

if ((Get-NetFirewallRule -DisplayGroup 'Remote Service Management').Enabled -contains 'False') {
    try {
        Send-Status -Message 'Starting to configure firewall for remote service management'

        Enable-NetFirewallRule -DisplayGroup 'Remote Service Management'
        
        Send-Status -Message 'Finished to configure firewall for remote service management'
    } catch {
        Send-Status -Message "Failed to configure firewall for remote service management: $_"
        return
    }
}

if (-not (Get-Command -Name choco -ErrorAction SilentlyContinue)) {
    try {
        Send-Status -Message 'Starting to install chocolatey'

        $null = Invoke-Expression -Command ([System.Net.WebClient]::new().DownloadString('https://chocolatey.org/install.ps1'))

        Send-Status -Message 'Finished to install chocolatey'
        Restart-Computer -Force
        return
    } catch {
        if ($_ -match 'a reboot is required') {
            Send-Status -Message "Rebooting to install chocolatey because: $_"
            Restart-Computer -Force
            return
        } elseif ($_ -match 'Forbidden') {
            # For more info see: https://docs.chocolatey.org/en-us/troubleshooting#im-getting-a-403-unauthorized-issue-when-attempting-to-use-the-community-package-repository
            # Fallback: use NuGet package from nuget.org for installation
            try {
                Send-Status -Message 'Starting to install chocolatey from NuGet'

                [System.Net.WebClient]::new().DownloadFile('https://www.nuget.org/api/v2/package/chocolatey', "$PSScriptRoot\chocolatey.zip")
                Expand-Archive -Path $PSScriptRoot\chocolatey.zip -DestinationPath $PSScriptRoot\chocolatey
                Unblock-File -Path $PSScriptRoot\chocolatey\tools\chocolateyInstall.ps1
                & $PSScriptRoot\chocolatey\tools\chocolateyInstall.ps1

                Send-Status -Message 'Finished to install chocolatey from NuGet'
            } catch {
                Send-Status -Message "Failed to install chocolatey from NuGet: $_"
                return
            }
        } else {
            Send-Status -Message "Failed to install chocolatey: $_"
            return
        }
    }
}

if (Get-Command -Name choco -ErrorAction SilentlyContinue) {
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

if ($env:COMPUTERNAME -ne 'DC' -and (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -notin 1, 3) {
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
    while ( $true ) { 
        try {
            $null = Get-ADUser -Filter *
            break
        } catch {
            Send-Status -Message 'Waiting for domain to be ready'
            Start-Sleep -Seconds 30
        }
    }

    if ($config.Domain.AdminName -and (Get-ADUser -Filter *).Name -notcontains $config.Domain.AdminName) {
        try {
            Send-Status -Message "Starting to create domain admin $($config.Domain.AdminName)"
    
            $adminPassword = ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force
            New-ADUser -Name $config.Domain.AdminName -AccountPassword $adminPassword -Enabled $true
            Add-ADGroupMember -Identity 'Domain Admins' -Members Admin

            Send-Status -Message "Finished to create domain admin $($config.Domain.AdminName)"
        } catch {
            Send-Status -Message "Failed to create domain admin $($config.Domain.AdminName): $_"
            return
        }
    }

    foreach ($user in $config.Domain.Users) {
        if ((Get-ADUser -Filter *).Name -notcontains $user.Name) {
            try {
                Send-Status -Message "Starting to create domain user $($user.Name)"

                $userPassword = ConvertTo-SecureString -String $user.Password -AsPlainText -Force
                New-ADUser -Name $user.Name -AccountPassword $userPassword -Enabled $true
                
                if ($user.ADGroups) {
                    foreach ($group in $user.ADGroups) {
                        if (-not (Get-ADGroup -Filter "Name -EQ '$group'" -ErrorAction SilentlyContinue)) {
                            New-ADGroup -Name $group -GroupCategory Security -GroupScope Global
                        }
                        Add-ADGroupMember -Identity $group -Members $user.Name
                    }
                }

                Send-Status -Message "Finished to create domain user $($user.Name)"
            } catch {
                Send-Status -Message "Failed to create domain user $($user.Name): $_"
                return
            }
        }
    }

    if ($config.FileServerDriveLetter -and (Get-PSDrive -PSProvider FileSystem).Name -notcontains $config.FileServerDriveLetter) {
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
    
    if ($config.FileServerDriveLetter -and -not (Test-Path -Path "$($config.FileServerDriveLetter):\FileServer")) {
        try {
            Send-Status -Message 'Starting to create file server'
    
            $accessParams = @{
                FullAccess   = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
                ChangeAccess = 'Everyone'
            }
    
            $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software" -ItemType Directory
            $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer\Software" -Name Software @accessParams

            $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Backup" -ItemType Directory
            $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer\Backup" -Name Backup @accessParams

            $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Temp" -ItemType Directory
            $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer\Temp" -Name Temp @accessParams
    
            Add-DnsServerResourceRecordCName -ComputerName dc -ZoneName $config.Domain.Name -HostNameAlias "dc.$($config.Domain.Name)" -Name fs
            
            Send-Status -Message 'Finished to create file server'
        } catch {
            Send-Status -Message "Failed to create file server: $_"
            return
        }
    }
}

if ($env:COMPUTERNAME -ne 'DC') {
    foreach ($user in $config.Domain.Users) {
        while ( $true ) { 
            try {
                $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
                if ([DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$($config.Domain.Name)", "(&(objectClass=user)(sAMAccountName=$($user.Name)))").FindOne()) {
                    break
                }
                Send-Status -Message "Waiting for domain controller to create the user $($user.Name)"
                Start-Sleep -Seconds 30
            } catch {
                Send-Status -Message "Waiting for domain controller to create the user $($user.Name): $_"
                Start-Sleep -Seconds 30
            }
        }
        foreach ($group in $user.LocalGroups) {
            if ("$($config.Domain.NetbiosName)\$($user.Name)" -notin (Get-LocalGroupMember -Group $group).Name) {
                try {
                    Send-Status -Message "Starting to add $($user.Name) to local group $group"

                    Add-LocalGroupMember -Group $group -Member "$($config.Domain.NetbiosName)\$($user.Name)"

                    Send-Status -Message "Finished to add $($user.Name) to local group $group"
                } catch {
                    Send-Status -Message "Failed to add $($user.Name) to local group $($group): $_"
                    return
                }
            }
        }            
    }
}

if (Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue) {
    try {
        Send-Status -Message 'Starting to disable server manager'

        $null = Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask

        Send-Status -Message 'Finished to disable server manager'
    } catch {
        Send-Status -Message "Failed to disable server manager: $_"
        return
    }
}

if ((Get-TimeZone).Id -ne 'W. Europe Standard Time') {
    try {
        Send-Status -Message 'Starting to set time zone'

        Set-Timezone -Id "W. Europe Standard Time"

        Send-Status -Message 'Finished to set time zone'
    } catch {
        Send-Status -Message "Failed to set time zone: $_"
        return
    }
}

if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge)) {
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
