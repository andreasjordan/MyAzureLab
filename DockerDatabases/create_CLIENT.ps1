# This file should be included from ..\init_DockerDatabases.ps1

Write-PSFMessage -Level Host -Message 'Creating virtual maschine CLIENT'
Send-MyAzureLabStatus -Message 'Creating virtual maschine CLIENT'
New-MyAzureLabVM -ComputerName CLIENT -SourceImage Windows11 -VMSize Standard_B2s_v2 -Credential $initCredential -EnableException

$psSession = New-MyAzureLabSession -ComputerName CLIENT -Credential $initCredential

Write-PSFMessage -Level Host -Message 'Setting up PSGallery and installing needed modules'
Send-MyAzureLabStatus -Message 'Setting up PSGallery and installing needed modules'
Invoke-Command -Session $psSession -ScriptBlock { 
    $ErrorActionPreference = 'Stop'
    $null = Install-PackageProvider -Name Nuget -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module -Name PSFramework, Posh-SSH, ImportExcel, Microsoft.PowerShell.ConsoleGuiTools, Mdbc
}

Write-PSFMessage -Level Host -Message 'Setting up choco and installing needed software'
Send-MyAzureLabStatus -Message 'Setting up choco and installing needed software'
Invoke-Command -Session $psSession -ScriptBlock { 
    $ErrorActionPreference = 'Stop'

    # Because I use a german system locally, I have to set the UI culture to prevent this error:
    #  The module 'Microsoft.PowerShell.Archive' could not be loaded. For more information, run 'Import-Module Microsoft.PowerShell.Archive'.
    #  Import-LocalizedData: Cannot find the Windows PowerShell data file 'ArchiveResources.psd1' in directory 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Archive\de-DE\', or in any parent culture directories.
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) *> $null
    choco install powershell-core notepadplusplus 7zip git vscode sql-server-management-studio --confirm --limitoutput --no-progress *> $null
}

# We need a new session, so that we get a new environment with the path to git beeing in the PATH.
$psSession | Remove-PSSession
$psSession = New-MyAzureLabSession -ComputerName CLIENT -Credential $initCredential

Write-PSFMessage -Level Host -Message 'Setting up git'
Send-MyAzureLabStatus -Message 'Setting up git'
Invoke-Command -Session $psSession -ScriptBlock { 
    $ErrorActionPreference = 'Stop'
    $null = New-Item -Path C:\GitHub -ItemType Directory
    Set-Location -Path C:\GitHub
    git clone --quiet https://github.com/andreasjordan/PowerShell-for-DBAs.git
    git clone --quiet https://github.com/andreasjordan/PowerShell-moves-Data-around.git
}

$psSession | Remove-PSSession

Write-PSFMessage -Level Host -Message 'Finished'
Send-MyAzureLabStatus -Message 'Finished'
