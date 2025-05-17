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

Send-Status -Message 'Waiting for domain controller to be ready'
while ( $true ) { 
    try {
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
        break
    } catch {
	    Start-Sleep -Seconds 30
    }
}

    try {
        Send-Status -Message 'Starting to configure users und CredSSP'

        #Add-LocalGroupMember -Group Administrators -Member "$($config.Domain.NetbiosName)\$($config.Domain.UserName)"
        foreach ($user in $config.Domain.UserName, 'SQLAdmin', 'SQLUser') {
            if ("$($config.Domain.NetbiosName)\$user" -notin (Get-LocalGroupMember -Group 'Remote Desktop Users').Name) {
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member "$($config.Domain.NetbiosName)\$user"
            }
            if ("$($config.Domain.NetbiosName)\$user" -notin (Get-LocalGroupMember -Group 'Remote Management Users').Name) {
                Add-LocalGroupMember -Group 'Remote Management Users' -Member "$($config.Domain.NetbiosName)\$user"
            }
        }
        foreach ($computer in $config.DelegateComputer) {
            $null = Enable-WSManCredSSP -Role Client -DelegateComputer "$computer.$($config.Domain.Name)", $computer -Force
        }

        Send-Status -Message 'Finished to configure users und CredSSP'
    } catch {
        Send-Status -Message "Failed to configure users und CredSSP: $_"
        return
    }

if ((Get-Command -Name git -ErrorAction SilentlyContinue) -and -not (Test-Path -Path C:\GitHub\dataplat\dbatools)) {
    try {
        Send-Status -Message 'Starting to clone dbatools repository'

        $null = New-Item -Path C:\GitHub\dataplat -ItemType Directory
        Push-Location -Path C:\GitHub\dataplat
        git clone https://github.com/dataplat/dbatools.git
        Pop-Location
        
        Send-Status -Message 'Finished to clone dbatools repository'
    } catch {
        Send-Status -Message "Failed to clone dbatools repository: $_"
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
