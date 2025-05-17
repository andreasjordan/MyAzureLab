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

if ($config.SQLServerDriveLetter -and (Get-PSDrive -PSProvider FileSystem).Name -notcontains $config.SQLServerDriveLetter) {
    try {
        Send-Status -Message 'Starting to prepare SQL Server drive'

        $disk = Get-Disk | Where-Object -Property PartitionStyle -EQ 'RAW' | Sort-Object -Property Number | Select-Object -First 1
        $disk | Initialize-Disk -PartitionStyle GPT
        $partition = $disk | New-Partition -UseMaximumSize -DriveLetter $config.SQLServerDriveLetter
        $null = $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "SQLServer"

        Send-Status -Message 'Finished to prepare SQL Server drive'
    } catch {
        Send-Status -Message "Failed to prepare SQL Server drive: $_"
        return
    }
}

Send-Status -Message 'Waiting for domain controller to be ready'
while ( $true ) { 
    try {
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
        if ([DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$($config.Domain.Name)", "(&(objectClass=user)(sAMAccountName=SQLAdmin))").FindOne()) {
            break
        }
 	    Start-Sleep -Seconds 30
        break
    } catch {
	    Start-Sleep -Seconds 30
    }
}

    try {
        Send-Status -Message 'Starting to configure users und CredSSP'

        if ("$($config.Domain.NetbiosName)\SQLAdmin" -notin (Get-LocalGroupMember -Group Administrators).Name) {
            Add-LocalGroupMember -Group Administrators -Member "$($config.Domain.NetbiosName)\SQLAdmin"
        }
        $null = Enable-WSManCredSSP -Role Server -Force
        'y' | winrm quickconfig

        Send-Status -Message 'Finished to configure users und CredSSP'
    } catch {
        Send-Status -Message "Failed to configure users und CredSSP: $_"
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
