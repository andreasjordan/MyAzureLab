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

try {
    Send-Status -Message 'Starting to configure firewall'

    # Create firewall rule based on source code of dbatools (https://github.com/dataplat/dbatools/blob/development/public/New-DbaFirewallRule.ps1)
    $ruleParams = @{
        DisplayName = 'SQL Server default instance'
        Name        = 'SQL Server default instance'
        Group       = 'SQL Server'
        Enabled     = 'True'
        Direction   = 'Inbound'
        Protocol    = 'TCP'
        LocalPort   = '1433'
    }
    $null = New-NetFirewallRule @ruleParams
    Send-Status -Message 'Finished to configure firewall'
} catch {
    Send-Status -Message "Failed to configure firewall: $_"
    return
}

try {
    Send-Status -Message 'Starting to configure system for dbatools tests'

    Install-Module -Name Pester -Force -SkipPublisherCheck -MaximumVersion 4.99
    Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck -MaximumVersion 1.18.2
    Install-Module -Name dbatools.library -Force
    
    $null = New-Item -Path C:\GitHub -ItemType Directory
    Set-Location -Path C:\GitHub
    git clone --quiet https://github.com/dataplat/dbatools.git
    git clone --quiet https://github.com/dataplat/appveyor-lab.git
    
    Import-Module -Name C:\GitHub\dbatools\dbatools.psd1 -DisableNameChecking
    Import-Module -Name C:\GitHub\dbatools\dbatools.psm1 -DisableNameChecking -Force
    Get-DbaService -Type Engine, Agent, SSAS, SSIS -EnableException | Stop-DbaService -Force -EnableException

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
