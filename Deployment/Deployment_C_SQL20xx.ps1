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

$ruleParams = @{
    DisplayName = 'SQL Server default instance'
    Name        = 'SQL Server default instance'
    Group       = 'SQL Server'
    Enabled     = 'True'
    Direction   = 'Inbound'
    Protocol    = 'TCP'
    LocalPort   = '1433'
}
if (-not (Get-NetFirewallRule -Name $ruleParams.Name -ErrorAction SilentlyContinue)) {
    try {
        Send-Status -Message 'Starting to configure firewall'

        # Create firewall rule based on source code of dbatools (https://github.com/dataplat/dbatools/blob/development/public/New-DbaFirewallRule.ps1)
        $null = New-NetFirewallRule @ruleParams

        Send-Status -Message 'Finished to configure firewall'
    } catch {
        Send-Status -Message "Failed to configure firewall: $_"
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
