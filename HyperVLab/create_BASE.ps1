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

New-MyAzureLabVM -ComputerName BASE -SourceImage WindowsServer2022 -VMSize Standard_E4s_v6 -Credential $initCredential -TrustedLaunch -EnableException


Send-Status -Message 'Configuring HyperV on BASE'

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ErrorAction Stop -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $null = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -WarningAction SilentlyContinue
    Restart-Computer -Force
}
$psSession | Remove-PSSession
Start-Sleep -Seconds 120


Send-Status -Message 'Installing AutomatedLab on BASE'

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ErrorAction Stop -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
    try {
        if ((Get-PackageProvider -ListAvailable).Name -notcontains 'Nuget') {
            $null = Install-PackageProvider -Name Nuget -Force
        }
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        if (-not (Get-Module -Name AutomatedLab -ListAvailable)) {
            Install-Module -Name AutomatedLab -AllowClobber -SkipPublisherCheck -Force
        }
        if (-not (Get-Module -Name Posh-SSH -ListAvailable)) {
            Install-Module -Name Posh-SSH
        }
        Import-Module -Name AutomatedLab
        New-LabSourcesFolder *> $null
        Enable-LabHostRemoting -Force *> $null
        reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f *> $null
    } catch {
        Write-Warning -Message "Error installing AutomatedLab: $_"
        throw $_
    }
}
$psSession | Remove-PSSession


Send-Status -Message 'Downloading ISOs to BASE'

$downloads = @(
    @{ Name = 'Windows2025'   ; URL = $Env:MyWIN2025URL ; FileName = 'WindowsServer2025_x64_EN_Eval.iso' }
    @{ Name = 'SQLServer2025' ; URL = $Env:MySQL2025URL ; FileName = 'SQLServer2025-x64-ENU.iso' }
    @{ Name = 'SQLServer2022' ; URL = $Env:MySQL2022URL ; FileName = 'enu_sql_server_2022_developer_edition_x64_dvd_7cacf733.iso' }
    @{ Name = 'SQLServer2019' ; URL = $Env:MySQL2019URL ; FileName = 'en_sql_server_2019_developer_x64_dvd_e5ade34a.iso' }
)

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ErrorAction Stop -ArgumentList $Env:MyWIN2025URL -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    Import-Module -Name AutomatedLab
}
foreach ($dl in $downloads) {
    Send-Status -Message "Downloading $($dl.Name)"
    Invoke-Command -Session $psSession -ErrorAction Stop -ArgumentList $dl.URL, $dl.FileName -ScriptBlock {
        param ($url, $fileName)
        ([System.Net.WebClient]::new()).DownloadFile($url, "$labSources\ISOs\$fileName")
    }
}
$psSession | Remove-PSSession


Send-Status -Message 'Configuring BASE'

$labScripts = @(
    'AlwaysOn_AG.ps1'
    'TestingDbatools.ps1'
)

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ErrorAction Stop -ScriptBlock { $null = New-Item -Path C:\LabScripts -ItemType Directory }
foreach ($labScript in $labScripts) {
    $labScriptContent = Get-Content -Path ".\HyperVLab\$labScript" -Raw
    Invoke-Command -Session $psSession -ScriptBlock { param($script, $name) Set-Content -Path "C:\LabScripts\$name" -Value $script } -ArgumentList $labScriptContent, $labScript
}
$psSession | Remove-PSSession

if ($env:MyStatusURL) {
    $psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
    Invoke-Command -Session $psSession -ErrorAction Stop -ScriptBlock { [Environment]::SetEnvironmentVariable('MyStatusURL', $args[0], 'Machine') } -ArgumentList $env:MyStatusURL
    $psSession | Remove-PSSession
}

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ErrorAction Stop -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $scheduledTaskActionParams = @{
        Execute  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Argument = '-ExecutionPolicy RemoteSigned -NonInteractive -File C:\LabScripts\TestingDbatools.ps1'
    }
    $scheduledTaskParams = @{
        TaskName = 'DeploymentAtStartup'
        Trigger  = New-ScheduledTaskTrigger -AtStartup
        User     = 'SYSTEM'
        Action   = New-ScheduledTaskAction @scheduledTaskActionParams
    }
    $null = Register-ScheduledTask @scheduledTaskParams
}
$psSession | Remove-PSSession

Restart-MyAzureLabVM -ComputerName BASE

Send-Status -Message 'Finished creating virtual maschine BASE'
