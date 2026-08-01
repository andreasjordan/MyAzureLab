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

function Save-File {
    Param([string]$Url, [string]$Path)
    if (Test-Path -Path $Path) {
        return
    }
    # Download to a temporary name and rename afterwards, so that an interrupted
    # download is not mistaken for a complete file on the next run
    ([System.Net.WebClient]::new()).DownloadFile($Url, "$Path.part")
    Move-Item -Path "$Path.part" -Destination $Path
}

Send-Status -Message 'Starting deployment'

$sqlSourcePath = "$($config.FileServer.DriveLetter):\$($config.FileServer.BaseFolder)\Software\SQLServer"

# Every step is tested on its own, so that an interrupted run continues where it stopped.
# Do not test $sqlSourcePath here: it is created by the first step and would then skip
# all the following steps on the next run.
try {
    Send-Status -Message 'Starting to fill file server with SQL Server sources'

    $adminAccountName = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
    $adminPassword = $config.Domain.AdminPassword
    $adminCredential = [PSCredential]::new($adminAccountName, (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

    foreach ($folder in "$sqlSourcePath\ISO", "$sqlSourcePath\CU", "$sqlSourcePath\SampleDatabases") {
        if (-not (Test-Path -Path $folder)) {
            $null = New-Item -Path $folder -ItemType Directory
        }
    }
    Save-File -Url 'https://raw.githubusercontent.com/andreasjordan/demos/master/dbatools/Get-CU.ps1' -Path "$sqlSourcePath\CU\Get-CU.ps1"

    # Naming convention for the SQL Server machines:
    # * A name containing a version, like SQL2019 or SQL2022, is a source machine. It is built
    #   from an Azure SQL Server image and therefore carries the setup sources in
    #   C:\SQLServerFull. Those are the machines we collect the sources from here.
    # * A name containing a two digit number, like SQL01 or SQL02, is a target machine. It
    #   either uses an Azure SQL Server image and already has an instance, or it uses a plain
    #   Windows image and gets its instances installed from the sources collected here.
    # So the filter below is on purpose: only source machines are of interest.
    foreach ($name in (Get-ADComputer -Filter 'Name -like "SQL20*"').Name) {
        $destination = "$sqlSourcePath\ISO\$($name.Replace('SQL', 'SQLServer'))"
        if (Test-Path -Path $destination) {
            continue
        }
        Send-Status -Message "Starting to fill file server with SQL Server sources from $name"
        $session = New-PSSession -ComputerName $name -Credential $adminCredential -UseSSL -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
        Invoke-Command -Session $session -ScriptBlock {
            if (-not (Get-SmbShare -Name SQLServerFull -ErrorAction SilentlyContinue)) {
                $null = New-SmbShare -Path C:\SQLServerFull -Name SQLServerFull
            }
        }
        # Copy to a temporary folder and rename afterwards, so that an interrupted copy
        # is not mistaken for a complete one on the next run
        if (Test-Path -Path "$destination.part") {
            Remove-Item -Path "$destination.part" -Recurse -Force
        }
        $null = New-Item -Path "$destination.part" -ItemType Directory
        Copy-Item -Path "\\$name\SQLServerFull\*" -Destination "$destination.part" -Recurse
        Rename-Item -Path "$destination.part" -NewName (Split-Path -Path $destination -Leaf)
        $session | Remove-PSSession
        # Not neeeded, because sources include CU
        # if ((Get-Module -ListAvailable).Name -notcontains 'dbatools') {
        #     Install-Module -Name dbatools
        # }
        # & "$sqlSourcePath\CU\Get-CU.ps1" -Version $name.Replace('SQL', '') -Path "$sqlSourcePath\CU"
    }

    Send-Status -Message 'Starting to fill file server with SQL Server sample databases'
    Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2022.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2022.bak"
    #Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2019.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2019.bak"
    #Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2017.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2017.bak"
    #Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2016.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2016.bak"
    #Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2014.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2014.bak"
    Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2012.bak' -Path "$sqlSourcePath\SampleDatabases\AdventureWorks2012.bak"
    #Save-File -Url 'https://github.com/Microsoft/sql-server-samples/releases/download/wide-world-importers-v1.0/WideWorldImporters-Full.bak' -Path "$sqlSourcePath\SampleDatabases\WideWorldImporters-Full.bak"
    #Save-File -Url 'https://downloads.brentozar.com/StackOverflow2010.7z' -Path "$sqlSourcePath\SampleDatabases\StackOverflow2010.7z"

    Send-Status -Message 'Finished to fill file server with SQL Server sources'
} catch {
    Send-Status -Message "Failed to fill file server with SQL Server sources: $_"
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
