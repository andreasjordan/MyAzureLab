# This file should be included from ..\init_DockerDatabases.ps1

Write-PSFMessage -Level Host -Message 'Creating virtual maschine DATABASES'
New-MyAzureLabVM -ComputerName DATABASES -SourceImage Ubuntu22 -VMSize Standard_E4s_v5 -Credential $initCredential -EnableException

Write-PSFMessage -Level Host -Message 'Downloading the repo PowerShell-for-DBAs'
$command = @(
    'sudo apt install curl unzip -y'
    'mkdir -p ~/GitHub'
    'curl -L -o repo.zip https://github.com/andreasjordan/PowerShell-for-DBAs/archive/refs/heads/main.zip'
    'unzip repo.zip -d ~/GitHub'
    'rm repo.zip'
    'mv ~/GitHub/PowerShell-for-DBAs-main ~/GitHub/PowerShell-for-DBAs'
)
Invoke-MyAzureLabSSHCommand -ComputerName DATABASES -Credential $initCredential -Command $command -EnableException

Write-PSFMessage -Level Host -Message 'Installing docker, 7zip and PowerShell modules'
$command = @(
    'curl -fsSL -o get-docker.sh https://get.docker.com'
    'sudo sh get-docker.sh'
    'rm get-docker.sh'
    'sudo sh ./GitHub/PowerShell-for-DBAs/WSL2/05_install_7zip.sh'
    'pwsh ./GitHub/PowerShell-for-DBAs/WSL2/06_install_pwsh_modules.ps1'
)
Invoke-MyAzureLabSSHCommand -ComputerName DATABASES -Credential $initCredential -Command $command -EnableException

Write-PSFMessage -Level Host -Message 'Pulling docker images'
$content = (Invoke-WebRequest -Uri https://raw.githubusercontent.com/andreasjordan/PowerShell-for-DBAs/refs/heads/main/WSL2/07_select_databases.ps1 -UseBasicParsing).Content.Split("`n")
$containerNames = $content | ForEach-Object -Process { if ($_ -match "ContainerName\s+=\s+'(.+)'") { $Matches[1]} }
$containerImages = $content | ForEach-Object -Process { if ($_ -match "ContainerImage\s+=\s+'(.+)'") { $Matches[1]} }
foreach ($image in $containerImages) {
    Write-PSFMessage -Level Host -Message "Pulling docker image $image"
    Invoke-MyAzureLabSSHCommand -ComputerName DATABASES -Credential $initCredential -Command "sudo docker pull --quiet $image" -TimeOut 1800 -EnableException
}

Write-PSFMessage -Level Host -Message 'Starting docker container'
$command = @(
#    'pwsh ./GitHub/PowerShell-for-DBAs/WSL2/07_select_databases.ps1 SQLServer Oracle MySQL PostgreSQL'
    "pwsh ./GitHub/PowerShell-for-DBAs/WSL2/07_select_databases.ps1 $containerNames"
    'pwsh ./GitHub/PowerShell-for-DBAs/WSL2/09_start_databases.ps1'
)
Invoke-MyAzureLabSSHCommand -ComputerName DATABASES -Credential $initCredential -Command $command -EnableException

Write-PSFMessage -Level Host -Message 'Setup sample databases and schemas'
$command = @(
    'pwsh ./GitHub/PowerShell-for-DBAs/PowerShell/01_SetupSampleDatabases.ps1'
    'pwsh ./GitHub/PowerShell-for-DBAs/PowerShell/02_SetupSampleSchemas.ps1'
)
Invoke-MyAzureLabSSHCommand -ComputerName DATABASES -Credential $initCredential -Command $command -EnableException

Write-PSFMessage -Level Host -Message 'Finished'
