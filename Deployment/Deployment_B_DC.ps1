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

if (-not (Test-Path -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer")) {
    try {
        Send-Status -Message 'Starting to fill file server with SQL Server sources'

        $adminAccountName = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
        $adminPassword = $config.Domain.AdminPassword
        $adminCredential = [PSCredential]::new($adminAccountName, (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

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
            # Not neeeded, because sources include CU
            # if ((Get-Module -ListAvailable).Name -notcontains 'dbatools') {
            #     Install-Module -Name dbatools
            # }
            # & "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU\Get-CU.ps1" -Version $name.Replace('SQL', '') -Path "$($config.FileServerDriveLetter):\FileServer\Software\SQLServer\CU"
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

try {
    Send-Status -Message 'Starting to remove startup task'

    Unregister-ScheduledTask -TaskName DeploymentAtStartup -Confirm:$false

    Send-Status -Message 'Finished to remove startup task'
} catch {
    Send-Status -Message "Failed to remove startup task: $_"
    return
}

Send-Status -Message 'Finished deployment'
