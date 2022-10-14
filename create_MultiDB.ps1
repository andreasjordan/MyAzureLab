$ErrorActionPreference = 'Stop'
Import-Module -Name PSFramework    # Install-Module -Name PSFramework   # Update-Module -Name PSFramework
Import-Module -Name Az             # Install-Module -Name Az            # Update-Module -Name Az
Import-Module -Name Posh-SSH       # Install-Module -Name Posh-SSH      # Update-Module -Name Posh-SSH
. .\MyAzureLab.ps1

# The following script is not publicly available, as it containes my personal setting.
# Just search for "$Env:MyAzure" in this script to find all the variables that I set there.
. .\MyAzureLabEnvironment.ps1        

$PSDefaultParameterValues = @{ "*-MyAzureLab*:EnableException" = $true }

<#

This Skript will setup my lab with Azure virtual maschines for the multi database environment based on docker.

It takes about an hour.

It will connect to Azure with
* a given acount name (`$accountId`)
* a given subscription (`$subscriptionName`)

It will then create the following objects.

A [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell) with
* a given name (`$resourceGroupName`)
* in a given location (`$location`)

A [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts) with
* the name "KeyVault<10 digit random number>"
* a self signed certificate named "<name of resource group>Certificate" to support connecting to the virtual maschines via WinRM

A [virtual network](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) with
* the name "VirtualNetwork"
* the address prefix "10.0.0.0/16"
* a subnet with the name "Default" and the address prefix "10.0.0.0/24"
* the IP address "10.0.0.10" for the domain controller

A [network security group](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) with
* the name "NetworkSecurityGroup"
* rules to allow communication from my home address to the network for RDP (port 3389), SSH (port 22) and WinRM (port 5986)

A set of [virtual maschines](https://docs.microsoft.com/en-us/azure/virtual-machines/):
* A server with
  * the name "MULTIDB"
  * Linux Ubuntu 22.04
  * Docker
  * PowerShell
* A workstation with
  * the name "CLIENT"
  * Windows 10
  * to be the only maschine to RDP in and do the lab work from there

#>

# Test for needed environment variables
if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription -and $Env:MyAzureInitialAdmin -and $Env:MyAzureInitialPassword) {
    Write-PSFMessage -Level Verbose -Message 'Environment is set'
} else {
    throw "Not all needed environment variables are set"
}

# Will be used with Connect-AzAccount
$privateAzureAccountParameters = @{
    AccountId    = $Env:MyAzureAccountId
    Subscription = $Env:MyAzureSubscription
}

# Name of resource group and location
# Will be used by MyAzureLab commands
$resourceGroupName = 'MultiDB'
$location = 'North Central US'


# Will be used by MyAzureLab commands
$initialAdmin    = $Env:MyAzureInitialAdmin     # Will be used when creating the virtual maschines
$initialPassword = $Env:MyAzureInitialPassword  # Will be used when creating the virtual maschines and for the certificate

$secretPassword = ConvertTo-SecureString -String $initialPassword -AsPlainText -Force
$credential = [PSCredential]::new($initialAdmin, $secretPassword)



# Part 1: Connecting

Write-PSFMessage -Level Host -Message 'Connecting to Azure'
$account = Connect-AzAccount @privateAzureAccountParameters
Write-PSFMessage -Level Verbose -Message "Connected to Azure with account '$($account.Context.Account.Id)' and subscription '$($account.Context.Subscription.Name)' in tenant '$($account.Context.Tenant.Id)'"



# Part 2: Setting up main infrastructure

# Removing resource group if it already exists
if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
    Write-PSFMessage -Level Host -Message 'Removing resource group, key vault and certificate'
    $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
    Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
    Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object Subject -eq "CN=$($resourceGroupName)Certificate" | Remove-Item
}

Write-PSFMessage -Level Host -Message 'Creating resource group'
$null = New-AzResourceGroup -Name $resourceGroupName -Location $location

Write-PSFMessage -Level Host -Message 'Creating key vault and certificate'
New-MyAzureLabKeyVault

Write-PSFMessage -Level Host -Message 'Creating network and security group'
New-MyAzureLabNetwork


# Part 3: Setting up virtual maschines MULTIDB and CLIENT
# https://azureprice.net/

# In case I need to recreate: Remove-MyAzureLabVM -ComputerName MULTIDB
Write-PSFMessage -Level Host -Message 'Creating virtual maschine MULTIDB'
New-MyAzureLabVM -ComputerName MULTIDB -SourceImage Ubuntu22 -VMSize Standard_E4ads_v5 -NoDomain

$session = New-MyAzureLabSession -ComputerName MULTIDB -Credential $credential

Write-PSFMessage -Level Host -Message 'Installing PowerShell'
$installPowerShell = @'
sudo apt-get update && \
sudo apt-get install -y wget apt-transport-https software-properties-common && \
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb" && \
sudo dpkg -i packages-microsoft-prod.deb && \
sudo apt-get update && \
sudo apt-get install -y powershell
'@
$result = Invoke-SSHCommand -SSHSession $session -Command $installPowerShell
if ($result.ExitStatus -ne 0) {
    throw "Error at installPowerShell"
}

Write-PSFMessage -Level Host -Message 'Installing and starting docker'
$installDocker = @'
sudo apt-get update && \
sudo apt-get install ca-certificates curl gnupg lsb-release && \
sudo mkdir -p /etc/apt/keyrings && \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
sudo apt-get update && \
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo service docker start
'@
$result = Invoke-SSHCommand -SSHSession $session -Command $installDocker
if ($result.ExitStatus -ne 0) {
    throw "Error at installDocker"
}

Write-PSFMessage -Level Host -Message 'Pulling docker images'
$images = @(
    'mcr.microsoft.com/mssql/server:2019-latest'
    'container-registry.oracle.com/database/express:latest'
    'mysql:latest'
    'mariadb:latest'
    'postgres:latest'
    'ibmcom/db2:latest'
    'ibmcom/informix-developer-database:latest'
)
foreach ($image in $images) {
    Write-PSFMessage -Level Host -Message "Pulling docker image $image"
    $result = Invoke-SSHCommand -SSHSession $session -Command "sudo docker pull --quiet $image" -TimeOut 1800
    if ($result.ExitStatus -ne 0) {
        throw "Error at pulling docker image $image"
    }
}

Write-PSFMessage -Level Host -Message 'Configuring Environment'
$configEnvironment = @'
pwsh <<"END_OF_PWSH"
$ProgressPreference = 'SilentlyContinue'
# Download GitHub repo with scripts to setup all containers
$null = New-Item -Path ~/GitHub -ItemType Directory
Invoke-WebRequest -Uri https://github.com/andreasjordan/PowerShell-for-DBAs/archive/refs/heads/main.zip -OutFile repo.zip -UseBasicParsing
Expand-Archive -Path repo.zip -DestinationPath ~/GitHub
Remove-Item -Path repo.zip
Rename-Item -Path ~/GitHub/PowerShell-for-DBAs-main -NewName PowerShell-for-DBAs
# Install PowerShell module dbatools for connection to SQL Server
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSFramework
# Download NuGet packages for connection to other database systems
$null = New-Item -Path ~/NuGet -ItemType Directory
foreach ($package in 'Oracle.ManagedDataAccess.Core', 'MySql.Data', 'Npgsql', 'Net.IBM.Data.Db2-lnx', 'IBM.Data.DB2.Core-lnx') { if (-not (Test-Path -Path ~/NuGet/$package)) { Invoke-WebRequest -Uri https://www.nuget.org/api/v2/package/$package -OutFile package.zip -UseBasicParsing ; Expand-Archive -Path package.zip -DestinationPath ~/NuGet/$package ; Remove-Item -Path package.zip } }
# Create directory for additional software
$null = New-Item -Path ~/Software -ItemType Directory
END_OF_PWSH
'@
$result = Invoke-SSHCommand -SSHSession $session -Command $configEnvironment
if ($result.ExitStatus -ne 0) {
    throw "Error at configEnvironment"
}

Write-PSFMessage -Level Host -Message 'Copying additional software'
$copyParams = @{
    ComputerName = 'MULTIDB'
    Credential   = $credential
    Path         = '..\PowerShell-for-DBAs\Software\INFO_CLT_SDK_LNX_X86_4.50.FC8.tar'
    Destination  = "/home/$($credential.UserName)/Software"
}
Copy-MyAzureLabItem @copyParams

#pwsh -c "./SetupServerWithDocker.ps1 -DBMS SQLServer, Oracle, MySQL, MariaDB, PostgreSQL"
#pwsh -c "./SetupServerWithDocker.ps1 -DBMS Db2, Informix"
Write-PSFMessage -Level Host -Message 'Creating container'
$createContainer = @'
export USE_SUDO=YES && \
cd ~/GitHub/PowerShell-for-DBAs/PowerShell/ && \
pwsh -c "./SetupServerWithDocker.ps1"
'@
$result = Invoke-SSHCommand -SSHSession $session -Command $createContainer -TimeOut 3600 -ShowStandardOutputStream -ShowErrorOutputStream
if ($result.ExitStatus -ne 0) {
    throw "Error at createContainer"
}

Write-PSFMessage -Level Host -Message 'Creating virtual maschine CLIENT'
New-MyAzureLabVM -ComputerName CLIENT -SourceImage Windows10 -NoDomain

Write-PSFMessage -Level Host -Message 'Finished'


# Part 4: Setting up CLIENT maschine ...
<#
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "CLIENT_PublicIP").IpAddress
mstsc.exe /v:$ipAddress /w:1920 /h:1200 /prompt

# Execute in an admin PowerShell:
$ErrorActionPreference = 'Stop'
$null = Install-PackageProvider -Name Nuget -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSFramework
Install-Module -Name Posh-SSH
Install-Module -Name dbatools
Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install powershell-core notepadplusplus git vscode vscode-powershell --confirm --limitoutput --no-progress

# Execute in normal PowerShell:
$ErrorActionPreference = 'Stop'
$null = New-Item -Path C:\GitHub -ItemType Directory
Set-Location -Path C:\GitHub
git clone https://github.com/andreasjordan/PowerShell-for-DBAs.git

#>



<#

# Start:
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name CLIENT_VM
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name MULTIDB_VM

# Connect:
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "CLIENT_PublicIP").IpAddress
mstsc.exe /v:$ipAddress /w:1920 /h:1200 /prompt

# Stop:
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name CLIENT_VM -Force
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name MULTIDB_VM -Force

#>