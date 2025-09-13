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

<#

try {
    Send-Status -Message 'Starting to install SQL Server instances for dbatools tests'

    Import-Module -Name dbatools
    $PSDefaultParameterValues['*-Dba*:EnableException'] = $true
    $PSDefaultParameterValues['*-Dba*:Confirm'] = $false
    Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

    $instanceParams = @{
        Feature            = 'Engine'
        Version            = 2022
        Configuration      = @{
            SqlMaxMemory = '2048'
            NpEnabled    = 1
        } 
        AuthenticationMode = 'Mixed'
        SaCredential       = [PSCredential]::new('sa', (ConvertTo-SecureString -String $config.Domain.AdminPassword -AsPlainText -Force))
        AdminAccount       = "$($config.Domain.NetbiosName)\$($config.Domain.AdminName)"
        IFI                = $true
        Path               = '\\fs\Software\SQLServer\ISO'
    }
    # That does not work, as the source files are from the official image and are fully patched. So we would need to download the RTM sources from somewhere.
    $instanceParams.UpdateSourcePath = '\\fs\Software\SQLServer\oldCU' # Get-DbaInstalledPatch.Tests.ps1 need an installable CU in instance1
    $null = Install-DbaInstance @instanceParams -SqlInstance localhost -ProductID '11111-00000-00000-00000-00000'
    $instanceParams.UpdateSourcePath = '\\fs\Software\SQLServer\CU'
    $null = Install-DbaInstance @instanceParams -SqlInstance localhost\dbatools2
    $null = Install-DbaInstance @instanceParams -SqlInstance localhost\dbatools3

    Send-Status -Message 'Finished to install SQL Server instances for dbatools tests'
} catch {
    Send-Status -Message "Failed to install SQL Server instances for dbatools tests: $_"
    return
}

try {
    Send-Status -Message 'Starting to configure SQL Server instances for dbatools tests'

    $sqlInstance = 'localhost', 'localhost\dbatools2', 'localhost\dbatools3'
    $null = Set-DbaSpConfigure -SqlInstance $sqlInstance -SqlCredential $instanceParams.SaCredential -Name IsSqlClrEnabled -Value 1
    $null = Set-DbaSpConfigure -SqlInstance $sqlInstance -SqlCredential $instanceParams.SaCredential -Name ClrStrictSecurity -Value 0
#    $null = Set-DbaNetworkConfiguration -SqlInstance $sqlInstance -EnableProtocol NamedPipes -RestartService

    $null = Enable-DbaAgHadr -SqlInstance $sqlInstance[2] -Force
    $server = Connect-DbaInstance -SqlInstance $sqlInstance[2] -SqlCredential $instanceParams.SaCredential
    $server.Query("IF NOT EXISTS (select * from sys.symmetric_keys where name like '%DatabaseMasterKey%') CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<StrongPassword>'")
    $server.Query("IF EXISTS ( SELECT * FROM sys.tcp_endpoints WHERE name = 'End_Mirroring') DROP ENDPOINT endpoint_mirroring")
    $server.Query("CREATE CERTIFICATE dbatoolsci_AGCert WITH SUBJECT = 'AG Certificate'")

    Send-Status -Message 'Finished to configure SQL Server instances for dbatools tests'
} catch {
    Send-Status -Message "Failed to configure SQL Server instances for dbatools tests: $_"
    return
}

#>

try {
    Send-Status -Message 'Starting to configure system for dbatools tests'

    Install-Module -Name Pester -Force -SkipPublisherCheck
    Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck -MaximumVersion 1.18.2

    $null = New-Item -Path C:\GitHub -ItemType Directory
    Push-Location -Path C:\GitHub
    git clone --quiet https://github.com/dataplat/dbatools.git
    git clone --quiet https://github.com/dataplat/appveyor-lab.git
    Pop-Location
    
    Send-Status -Message 'Finished to configure system for dbatools tests'
} catch {
    Send-Status -Message "Failed to configure system for dbatools tests: $_"
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
