# This file should be included from ..\init_HyperVLab.ps1

Write-PSFMessage -Level Host -Message 'Creating virtual maschine BASE'

New-MyAzureLabVM -ComputerName BASE -SourceImage WindowsServer2022 -VMSize Standard_E2s_v6 -Credential $initCredential -TrustedLaunch -EnableException


Write-PSFMessage -Level Host -Message 'Configuring HyperV on BASE'

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ScriptBlock {
    $ProgressPreference = 'SilentlyContinue'
    $null = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -WarningAction SilentlyContinue
    Restart-Computer -Force
}
$psSession | Remove-PSSession
Start-Sleep -Seconds 30


Write-PSFMessage -Level Host -Message 'Installing AutomatedLab on BASE'

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ScriptBlock {
    $ProgressPreference = 'SilentlyContinue'
    $null = Install-PackageProvider -Name Nuget -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module -Name AutomatedLab -AllowClobber -SkipPublisherCheck -Force
    Install-Module -Name Posh-SSH
    [Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
    $env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'
    Set-PSFConfig -Module AutomatedLab -Name LabSourcesLocation -Description 'Location of lab sources folder' -Validation string -Value 'C:\AutomatedLab-Sources' -PassThru | Register-PSFConfig
    Set-PSFConfig -Module AutomatedLab -Name VmPath             -Description 'Location of lab vm folder'      -Validation string -Value 'C:\AutomatedLab-VMs'     -PassThru | Register-PSFConfig
    Import-Module -Name AutomatedLab
    New-LabSourcesFolder *> $null
    Enable-LabHostRemoting -Force *> $null
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f *> $null
}
$psSession | Remove-PSSession


Write-PSFMessage -Level Host -Message 'Downloading ISOs to BASE'

$downloads = @(
    @{ Name = 'Windows2025'   ; URL = $Env:MyWIN2025URL ; FileName = 'WindowsServer2025_x64_EN_Eval.iso' }
    @{ Name = 'SQLServer2025' ; URL = $Env:MySQL2025URL ; FileName = 'SQLServer2025-x64-ENU.iso' }
    @{ Name = 'SQLServer2022' ; URL = $Env:MySQL2022URL ; FileName = 'enu_sql_server_2022_developer_edition_x64_dvd_7cacf733.iso' }
    @{ Name = 'SQLServer2019' ; URL = $Env:MySQL2019URL ; FileName = 'en_sql_server_2019_developer_x64_dvd_e5ade34a.iso' }
)

$psSession = New-MyAzureLabSession -ComputerName BASE -Credential $initCredential
Invoke-Command -Session $psSession -ArgumentList $Env:MyWIN2025URL -ScriptBlock {
    Import-Module -Name AutomatedLab
}
foreach ($dl in $downloads) {
    Write-PSFMessage -Level Host -Message "Downloading $($dl.Name)"
    Invoke-Command -Session $psSession -ArgumentList $dl.URL, $dl.FileName -ScriptBlock {
        param ($url, $fileName)
        ([System.Net.WebClient]::new()).DownloadFile($url, "$labSources\ISOs\$fileName")
    }
}
$psSession | Remove-PSSession


Write-PSFMessage -Level Host -Message 'Finished creating virtual maschine BASE'
