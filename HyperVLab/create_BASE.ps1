# This file should be included from ..\init_HyperVLab.ps1

function Send-Status {
    Param([string]$Message)
    Write-PSFMessage -Level Host -Message $Message
    if ($env:MyStatusUrl) {
        $requestParams = @{
            Uri             = $env:MyStatusUrl
            Method          = 'Post'
            ContentType     = 'application/json'
            Body            = @{
                IP      = '127.0.0.1'
                Host    = 'localhost'
                Message = $Message
            } | ConvertTo-Json -Compress
            UseBasicParsing = $true
        }
        try {
            $null = Invoke-WebRequest @requestParams
        } catch {
            Write-Warning -Message "Failed to send status: $_"
        }
    }
}

trap {
    Send-Status -Message "Error in create_BASE.ps1: $_"
    throw $_
}

Send-Status -Message 'Creating virtual maschine BASE'
New-MyAzureLabVM -ComputerName BASE -SourceImage WindowsServer2022 -VMSize Standard_E4s_v6 -Credential $initCredential -TrustedLaunch -AutomatedLab -EnableException

Send-Status -Message 'Configuring virtual maschine BASE'
Invoke-MyAzureLabCommand -ComputerName BASE -Credential $initCredential -ArgumentList $labConfig -ScriptBlock {
    param($config)
    $ProgressPreference = 'SilentlyContinue'
    if (-not (Test-Path -Path 'C:\LabScripts')) {
        $null = New-Item -Path 'C:\LabScripts' -ItemType Directory
    }
    Set-Content -Path "C:\LabScripts\$($config.LabScript.Name)" -Value $config.LabScript.Content
    Import-Module -Name AutomatedLab
    foreach ($dl in $config.ISODownloads) {
        ([System.Net.WebClient]::new()).DownloadFile($dl.URL, "$labSources\ISOs\$($dl.FileName)")
    }
    foreach ($envVar in $config.EnvironmentVariables.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($envVar.Key, $envVar.Value, 'Machine')
    }
}

Invoke-MyAzureLabCommand -ComputerName BASE -Credential $initCredential -ArgumentList $labConfig -ScriptBlock {
    param($config)
    $scheduledTaskActionParams = @{
        Execute  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Argument = "-ExecutionPolicy RemoteSigned -NonInteractive -File C:\LabScripts\$($config.LabScript.Name)"
    }
    $scheduledTaskParams = @{
        TaskName = 'DeploymentAtStartup'
        Trigger  = New-ScheduledTaskTrigger -AtStartup
        User     = 'SYSTEM'
        Action   = New-ScheduledTaskAction @scheduledTaskActionParams
    }
    $null = Register-ScheduledTask @scheduledTaskParams
}
Restart-MyAzureLabVM -ComputerName BASE

Send-Status -Message 'Finished creating virtual maschine BASE'
