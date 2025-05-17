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

Send-Status -Message 'Waiting for domain to be ready'
while ( $true ) { 
    try {
        $null = Get-ADUser -Filter *
        break
    } catch {
	    Start-Sleep -Seconds 30
    }
}

if ((Get-ADUser -Filter *).Name -notcontains 'SQLAdmin') {
    try {
        Send-Status -Message 'Starting to create ad users for SQL Server'

        $adminPassword = ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force
        $sqlUserOU = New-ADOrganizationalUnit -Name SqlUser -ProtectedFromAccidentalDeletion:$false -PassThru
        New-ADUser -Name SQLUser -AccountPassword $adminPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADUser -Name SQLAdmin -AccountPassword $adminPassword -Enabled $true -Path $sqlUserOU.DistinguishedName
        New-ADGroup -Name SQLServiceAccounts -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName
        New-ADGroup -Name SQLUsers -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName
        New-ADGroup -Name SQLAdmins -GroupCategory Security -GroupScope Global -Path $sqlUserOU.DistinguishedName
        Add-ADGroupMember -Identity SQLUsers -Members SQLUser
        Add-ADGroupMember -Identity SQLAdmins -Members SQLAdmin
        #Add-ADGroupMember -Identity SQLAdmins -Members $config.Domain.UserName
        foreach ($sam in (Get-ADComputer -Filter 'name -like "SQL*"').SamAccountName) {
            Add-ADGroupMember -Identity SQLServiceAccounts -Members $sam
        }

        Send-Status -Message 'Finished to create ad users for SQL Server'
    } catch {
        Send-Status -Message "Failed to create ad users for SQL Server: $_"
        return
    }
}

if (-not (Test-Path -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer")) {
    try {
        Send-Status -Message 'Starting to fill file server with SQL Server sources'

        $adminAccountName = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
        $adminPassword = $config.Domain.AdminPassword
        $adminCredential = [PSCredential]::new($adminAccountName, (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

        $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer" -ItemType Directory
        $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\ISO" -ItemType Directory
        $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU" -ItemType Directory
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/andreasjordan/demos/master/dbatools/Get-CU.ps1' -OutFile "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU\Get-CU.ps1"

        foreach ($name in (Get-ADComputer -Filter 'Name -like "SQL20*"').Name) {
            Send-Status -Message "Starting to fill file server with SQL Server sources from $name"
            $session = New-PSSession -ComputerName $name -Credential $adminCredential -UseSSL -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
            Invoke-Command -Session $session -ScriptBlock { $null = New-SmbShare -Path C:\SQLServerFull -Name SQLServerFull }
            $destination = "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\ISO\$($name.Replace('SQL', 'SQLServer'))"
            $null = New-Item -Path $destination -ItemType Directory
            Copy-Item -Path "\\$name\SQLServerFull\*" -Destination $destination -Recurse
            $session | Remove-PSSession
            & "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU\Get-CU.ps1" -Version $name.Replace('SQL', '') -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU" -Last 2
        }

        Send-Status -Message 'Starting to fill file server with SQL Server sample databases'
        $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases" -ItemType Directory
        ([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2022.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2022.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2019.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2019.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2017.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2017.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2016.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2016.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2014.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2014.bak")
        ([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2012.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\AdventureWorks2012.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://github.com/Microsoft/sql-server-samples/releases/download/wide-world-importers-v1.0/WideWorldImporters-Full.bak', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\WideWorldImporters-Full.bak")
        #([System.Net.WebClient]::new()).DownloadFile('https://downloads.brentozar.com/StackOverflow2010.7z', "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\SampleDatabases\StackOverflow2010.7z")

        Send-Status -Message 'Finished to fill file server with SQL Server sources'
    } catch {
        Send-Status -Message "Failed to fill file server with SQL Server sources: $_"
        return
    }
}

if (-not (Test-Path -Path "$($config.FileServerDriveLetter):\FileServer\Backup")) {
    try {
        Send-Status -Message 'Starting to create backup share'

        $null = New-Item -Path "$($config.FileServerDriveLetter):\FileServer\Backup" -ItemType Directory
        $null = New-SmbShare -Path "$($config.FileServerDriveLetter):\FileServer\Backup" -Name Backup
        $null = Grant-SmbShareAccess -Name Backup -AccountName $adminAccountName -AccessRight Full -Force
        $null = Grant-SmbShareAccess -Name Backup -AccountName SQLServiceAccounts -AccessRight Change -Force    
        
        Send-Status -Message 'Finished to create backup share'
    } catch {
        Send-Status -Message "Failed to create backup share: $_"
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
