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
    Send-Status -Message 'Starting to install SQL Server instance'

    Import-Module -Name dbatools
    $PSDefaultParameterValues['*-Dba*:EnableException'] = $true
    $PSDefaultParameterValues['*-Dba*:Confirm'] = $false

    $credential = [PSCredential]::new("$($config.Domain.NetbiosName)\$($config.Domain.UserName)", (ConvertTo-SecureString -String $config.Domain.UserPassword -AsPlainText -Force))

    $computerName = ([DbaInstance]$config.SQLServer.SqlInstance).ComputerName
    $instanceName = ([DbaInstance]$config.SQLServer.SqlInstance).InstanceName
    $sqlInstance = $computerName
    if ($instanceName -ne 'MSSQLSERVER') {
        $sqlInstance += "\$instanceName"
    }
    $version = [int]$computerName.Replace('SQL', '')

    'Getting Services'
    $services = Get-DbaService -ComputerName $computerName -Credential $credential -Type Engine
    $service = $services | Where-Object { $_.ComputerName -eq $computerName -and $_.InstanceName -eq $instanceName }
    if ($service) {
        Send-Status -Message 'Starting to uninstall SQL Server instance'
        $instanceParams = @{
            SqlInstance        = $sqlInstance
            Version            = $version
            Configuration      = @{ ACTION = 'Uninstall' } 
            Path               = '\\fs\Software\SQLServer\ISO'
            Restart            = $true
            EnableException    = $false
            Credential         = $credential
        }
        'Starting Uninstall'
        $result = Install-DbaInstance @instanceParams
        $result | Select-Object -Property ComputerName, InstanceName, Successful, Restarted, Notes, ExitCode, ExitMessage | ConvertTo-Json | Add-Content -Path $PSScriptRoot\InstallDbaInstance.txt
        if (-not $result.Successful) {
            Send-Status -Message "Failed to uninstall SQL Server instance: $($result.ExitCode) $($result.ExitMessage)"
            return
        }

        $computerName = ([DbaInstance]$config.SQLServer.SqlInstance).ComputerName
        $instancePath = $service.BinaryPath -replace '"(.*)\\MSSQL\\Binn.*', '$1'
        Invoke-Command -ComputerName $computerName -ArgumentList $instancePath -Authentication Credssp -Credential $credential -ScriptBlock {
            Param([string]$Path)
            Remove-Item -Path $Path -Recurse -Force
        }

        Send-Status -Message 'Starting to install SQL Server instance'
    }

    $instanceParams = @{
        SqlInstance        = $sqlInstance
        Feature            = 'Engine'
        Version            = $version
        Configuration      = @{
            SqlSvcInstantFileInit = 'True'
            SqlMaxMemory          = '2048'
        } 
        SqlCollation       = 'Latin1_General_100_CI_AS_SC'  # For german systems: Latin1_General_CI_AS
        InstancePath       = $config.SQLServer.InstancePath
        AuthenticationMode = 'Mixed'
        AdminAccount       = $config.SQLServer.AdminAccount
        Path               = '\\fs\Software\SQLServer\ISO'
        UpdateSourcePath   = '\\fs\Software\SQLServer\CU'
        Restart            = $true
        EnableException    = $false
        Credential         = $credential
    }
    'Starting Install'
    $result = Install-DbaInstance @instanceParams
    $result | Select-Object -Property ComputerName, InstanceName, Successful, Restarted, Notes, ExitCode, ExitMessage | ConvertTo-Json | Add-Content -Path $PSScriptRoot\InstallDbaInstance.txt
    if (-not $result.Successful) {
        Send-Status -Message "Failed to install SQL Server instance: $($result.ExitCode) $($result.ExitMessage)"
        return
    }

    'New-DbaFirewallRule'
    $null = New-DbaFirewallRule -SqlInstance $sqlInstance -Credential $credential

    'Connect-DbaInstance'
    $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $credential -NonPooledConnection

    Send-Status -Message 'Finished to install SQL Server instance'
} catch {
    Send-Status -Message "Failed to install SQL Server instance: $_"
    return
}

try {
    Send-Status -Message 'Starting to configure SQL Server instance'

    'Set-DbaLogin'
    $null = Set-DbaLogin -SqlInstance $server -Login sa -Disable
    'Set-DbaSpConfigure'
    $null = Set-DbaSpConfigure -SqlInstance $server -Name CostThresholdForParallelism -Value 50
    $null = Set-DbaSpConfigure -SqlInstance $server -Name DefaultBackupCompression -Value 1
    $null = Set-DbaSpConfigure -SqlInstance $server -Name BackupChecksumDefault -Value 1

    Send-Status -Message 'Finished to configure SQL Server instance'
} catch {
    Send-Status -Message "Failed to configure SQL Server instance: $_"
    return
}

try {
    Send-Status -Message 'Starting to install tools'

    'Install-DbaFirstResponderKit'
    $null = Install-DbaFirstResponderKit -SqlInstance $server -OnlyScript Install-Core-Blitz-With-Query-Store.sql
    'Install-DbaMaintenanceSolution'
    $null = Install-DbaMaintenanceSolution -SqlInstance $server -Database master -BackupLocation \\fs\Backup -CleanupTime 3 -LogToTable -InstallJobs
    'Install-DbaWhoIsActive'
    $null = Install-DbaWhoIsActive -SqlInstance $server -Database master 

    Send-Status -Message 'Finished to install tools'
} catch {
    Send-Status -Message "Failed to install tools: $_"
    return
}

try {
    Send-Status -Message 'Starting to restore sample databases'

    'Restore-DbaDatabase'
    $null = Restore-DbaDatabase -SqlInstance $server -Path \\fs\Software\SQLServer\SampleDatabases\AdventureWorks2022.bak -DatabaseName AdventureWorks -ExecuteAs sa
    # Bug: Restore-DbaDatabase terminates the connection
    $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $credential -NonPooledConnection
    $null = Restore-DbaDatabase -SqlInstance $server -Path \\fs\Software\SQLServer\SampleDatabases\WideWorldImporters-Full.bak -DatabaseName WideWorldImporters -ExecuteAs sa
    $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $credential -NonPooledConnection

    <#
    'Invoke-Command'
    Invoke-Command -ComputerName $computerName -ArgumentList $server.DefaultFile -Authentication Credssp -Credential $credential -ScriptBlock {
        Param([string]$DefaultFile)
        Set-Location -Path $DefaultFile
        $null = & 'C:\Program Files\7-Zip\7z.exe' e \\fs\Software\SQLServer\SampleDatabases\StackOverflow2010.7z *
        Remove-Item -Path .\Readme_2010.txt
    }
    $fileStructure = [System.Collections.Specialized.StringCollection]::new()
    $null = $fileStructure.Add("$($server.DefaultFile)\StackOverflow2010.mdf")
    $null = $filestructure.Add("$($server.DefaultFile)\StackOverflow2010_log.ldf")
    'Mount-DbaDatabase'
    $null = Mount-DbaDatabase -SqlInstance $server -Database StackOverflow -FileStructure $fileStructure -DatabaseOwner sa
    'Invoke-DbaDbUpgrade'
    $null = Invoke-DbaDbUpgrade -SqlInstance $server -Database StackOverflow -NoCheckDb
    'Set-DbaDbRecoveryModel'
    $null = Set-DbaDbRecoveryModel -SqlInstance $server -Database StackOverflow -RecoveryModel Full
    'Invoke-DbaQuery'
    $null = Invoke-DbaQuery -SqlInstance $server -Database master -Query 'ALTER DATABASE [StackOverflow] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE'
    'Set-DbaDbQueryStoreOption'
    $null = Set-DbaDbQueryStoreOption -SqlInstance $server -Database StackOverflow -State ReadWrite
    # Set-DbaDbQueryStoreOption setzt die aktuelle Datenbank von master auf StackOverflow, vermutlich durch $db.Query($query, $db.Name)
    # Daher hier erstmal ganz zum Schluss einsortiert.
    #>
    
    Send-Status -Message 'Finished to restore sample databases'
} catch {
    Send-Status -Message "Failed to restore sample databases: $_"
    return
}

try {
    Send-Status -Message 'Starting to backup sample databases'

    'Start-DbaAgentJob'
    $null = Start-DbaAgentJob -SqlInstance $server -Job 'DatabaseBackup - USER_DATABASES - FULL' -Wait

    Send-Status -Message 'Finished to backup sample databases'
} catch {
    Send-Status -Message "Failed to backup sample databases: $_"
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
