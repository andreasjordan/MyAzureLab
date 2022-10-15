$ErrorActionPreference = 'Stop'
Import-Module -Name PSFramework    # Install-Module -Name PSFramework   # Update-Module -Name PSFramework
Import-Module -Name Az             # Install-Module -Name Az            # Update-Module -Name Az
. .\MyAzureLab.ps1

# The following script is not publicly available, as it containes my personal setting.
# Just search for "$Env:MyAzure" in this script to find all the variables that I set there.
. .\MyAzureLabEnvironment.ps1        

$PSDefaultParameterValues = @{ "*-MyAzureLab*:EnableException" = $true }

<#

This Skript will setup my lab with Azure virtual maschines to test SQL Server instances in a Windows Failover Cluster.

It takes about half an hour.

It will connect to Azure with
* a given acount name (`$accountId`)
* a given subscription (`$subscriptionName`)

It will then create the following objects.

A [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell) with
* a given name (`$resourceGroupName`)
* in a given location (`$location`)
* within a given subscription (`$subscription`)

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
* rules to allow communication from my home address to the network for WinRM (Port 5986) and RDP (Port 3389).

A set of [virtual maschines](https://docs.microsoft.com/en-us/azure/virtual-machines/):
* All with VM size "Standard_B2s"
* A domain controller with
  * the name "DC"
  * Windows Server 2016
  * AD DS configured for a given domain name (`$domainName`)
* A workstation with
  * the name "ADMIN"
  * Windows 10
  * to be the only maschine to RDP in and do the lab work from there
* Two windows servers with
  * the names "SQL01" and "SQL02"
  * Windows Server 2016
  * joined to the domain

#>

# Test for needed environment variables
if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription -and $Env:MyAzureInitialAdmin -and $Env:MyAzureInitialPassword -and $Env:MyAzureDomainName -and $Env:MyAzureInitialAdmin -and $Env:MyAzureInitialPassword -and $Env:MyAzurePassword) {
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
$resourceGroupName = 'FailoverCluster'
$location = 'North Central US'

# Will be used by MyAzureLab commands
$initialAdmin    = $Env:MyAzureInitialAdmin     # Will be used when creating the virtual maschines
$initialPassword = $Env:MyAzureInitialPassword  # Will be used when creating the virtual maschines and for the certificate

# Configuration of the created active directory domain
# Will be used by MyAzureLab commands
$domainConfiguration = @{
    DomainName      = $Env:MyAzureDomainName       # First part in upper cases will be used as NetBiosName
    InitialAdmin    = $Env:MyAzureInitialAdmin     # Will be used when creating the virtual maschines
    InitialPassword = $Env:MyAzureInitialPassword  # Will be used when creating the virtual maschines and for the certificate
    Password        = $Env:MyAzurePassword         # Will be used when creating additional users
    OUs = @(                              # List of organizational units that will be created
        @{
            Name = 'AdminComputer'
        }
        @{
            Name  = 'AdminUser'
            Groups = @(                   # List of security groups that will be created inside of the organizational unit
                @{
                    Name    = 'Admins'
                    Members = @(          # List of users that will be created inside of the organizational unit and added as member of the security group
                        'Admin'
                        'GlobalAdmin'
                        'LocalAdmin'
                    )
                }
            )
        }
        @{
            Name = 'SqlComputer'
        }
        @{
            Name   = 'SqlUser'
            Groups = @(
                @{
                    Name    = 'SQLServiceAccounts'
                    Members = @(
                        'SQLServer'
                        'SQLSrv1'
                        'SQLSrv2'
                        'SQLSrv3'
                        'SQLSrv4'
                        'SQLSrv5'
                    )
                }
                @{
                    Name    = 'SQLAdmins'
                    Members = @(
                        'SQLAdmin'
                    )
                }
                @{
                    Name    = 'SQLUsers'
                    Members = @(
                        'SQLUser1'
                        'SQLUser2'
                        'SQLUser3'
                        'SQLUser4'
                        'SQLUser5'
                    )
                }
            )
        }
    )
    GroupMembers = @(                     # List of users that will be added as member of the named security groups
        @{
            Group   = 'Domain Admins'
            Members = @( 'Admin' )
        }
    )
}

# Will be used by MyAzureLab commands
$secretPassword = ConvertTo-SecureString -String $domainConfiguration.InitialPassword -AsPlainText -Force
$credential = [PSCredential]::new($domainConfiguration.InitialAdmin, $secretPassword)
$domainCredential = [PSCredential]::new("$($domainConfiguration.InitialAdmin)@$($domainConfiguration.DomainName)", $secretPassword)



# Part 1: Connecting...

Write-PSFMessage -Level Host -Message 'Connecting to Azure'
$account = Connect-AzAccount @privateAzureAccountParameters
Write-PSFMessage -Level Verbose -Message "Connected to Azure with account '$($account.Context.Account.Id)' and subscription '$($account.Context.Subscription.Name)' in tenant '$($account.Context.Tenant.Id)'"



# Part 2: Setting up main infrastructure ...

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



# Part 3: Setting up virtual maschines DC and ADMIN ...
# https://azureprice.net/

Write-PSFMessage -Level Host -Message 'Creating virtual maschine DC'
New-MyAzureLabVM -ComputerName DC -SourceImage WindowsServer2016

Write-PSFMessage -Level Host -Message 'Creating virtual maschine ADMIN'
New-MyAzureLabVM -ComputerName ADMIN -SourceImage Windows10 -OrganizationalUnit 'AdminComputer'



# Part 4: Adding SQL Server maschines ...

Write-PSFMessage -Level Host -Message 'Creating virtual maschines SQL01 and SQL02'
New-MyAzureLabVM -ComputerName SQL01 -SourceImage WindowsServer2016 -OrganizationalUnit 'SqlComputer'
New-MyAzureLabVM -ComputerName SQL02 -SourceImage WindowsServer2016 -OrganizationalUnit 'SqlComputer'



# Part 5: Adding SQL Server sources ...

Write-PSFMessage -Level Host -Message 'Adding SQL Server sources for version 2017 and 2019, sample databases and cumulative updates'

# Instead of the following lines, you can use this instead:
# Add-MyAzureLabSQLSources -Version 2017, 2019

# But I have a data disk that I will use:
Write-PSFMessage -Level Host -Message "Mounting data disk to virtual maschine DC"
$vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name DC_VM
$dataDisk = Get-AzDisk -ResourceGroupName DataDisk -DiskName datadisk
$vm = Add-AzVMDataDisk -VM $vm -Name datadisk -CreateOption Attach -ManagedDiskId $dataDisk.Id -Lun 1
$result = Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm
Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

Write-PSFMessage -Level Host -Message "Copying SQL Server source files from data disk"
$psSession = New-MyAzureLabSession -ComputerName DC -Credential $domainCredential
Invoke-Command -Session $psSession -ScriptBlock { 
    $ErrorActionPreference = 'Stop'
    Get-Partition -Volume (Get-Volume -FileSystemLabel Daten) | Set-Partition -NewDriveLetter S
    Remove-Item -Path C:\FileServer\Software\SQLServer\ISO\* -Recurse
    Copy-Item -Path S:\Software\SQLServer* -Destination C:\FileServer\Software\SQLServer\ISO -Recurse
}

Write-PSFMessage -Level Host -Message "Unmounting data disk from virtual maschine DC"
$vm = Remove-AzVMDataDisk -VM $vm -DataDiskNames datadisk 
$result = Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm
Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

Write-PSFMessage -Level Host -Message 'Downloading SQL Server sample databases'
Invoke-Command -Session $psSession -ScriptBlock {
    # We need to use DC as file server hostname because we don't have CredSSP and must use local hostname
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2019.bak -OutFile \\DC\SampleDatabases\AdventureWorks2019.bak -UseBasicParsing
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2017.bak -OutFile \\DC\SampleDatabases\AdventureWorks2017.bak -UseBasicParsing
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2016.bak -OutFile \\DC\SampleDatabases\AdventureWorks2016.bak -UseBasicParsing
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2014.bak -OutFile \\DC\SampleDatabases\AdventureWorks2014.bak -UseBasicParsing
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2012.bak -OutFile \\DC\SampleDatabases\AdventureWorks2012.bak -UseBasicParsing
    Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/wide-world-importers-v1.0/WideWorldImporters-Full.bak -OutFile \\DC\SampleDatabases\WideWorldImporters-Full.bak -UseBasicParsing
}

Write-PSFMessage -Level Host -Message 'Installing dbatools and downloading SQL Server cumulative updates'
Invoke-Command -Session $psSession -ScriptBlock {
    $null = Install-PackageProvider -Name Nuget -Force
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module -Name dbatools
    # We need to use DC as file server hostname because we don't have CredSSP and must use local hostname
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/andreasjordan/demos/master/dbatools/Get-CU.ps1 -OutFile \\DC\Software\SQLServer\CU\Get-CU.ps1 -UseBasicParsing
    \\DC\Software\SQLServer\CU\Get-CU.ps1 -Version 2017, 2019 -Path \\DC\Software\SQLServer\CU | Out-Null
}

$psSession | Remove-PSSession


Write-PSFMessage -Level Host -Message 'finished'


# Part 5: Setting up ADMIN maschine ...
<#
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "ADMIN_PublicIP").IpAddress
mstsc.exe /v:$ipAddress /w:1920 /h:1200 /prompt

# Login as the domain admin, not the local admin!

# Execute in an admin PowerShell:
$ErrorActionPreference = 'Stop'

Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0

$null = Install-PackageProvider -Name Nuget -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSFramework
Install-Module -Name dbatools

Invoke-Expression -Command ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install 7zip notepadplusplus git vscode vscode-powershell googlechrome sql-server-management-studio --confirm --limitoutput --no-progress

# Execute in a normal PowerShell:

$ErrorActionPreference = 'Stop'
$null = New-Item -Path C:\GitHub -ItemType Directory
Set-Location -Path C:\GitHub
git clone https://github.com/andreasjordan/demos.git


#>


<#

# Start:
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name DC_VM
Start-Sleep -Seconds 30
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name ADMIN_VM
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name SQL01_VM
$null = Start-AzVM -ResourceGroupName $resourceGroupName -Name SQL02_VM

# Connect:
$ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "ADMIN_PublicIP").IpAddress
mstsc.exe /v:$ipAddress /w:1920 /h:1200 /prompt

# Stop:
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name SQL01_VM -Force
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name SQL02_VM -Force
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name ADMIN_VM -Force
Start-Sleep -Seconds 30
$null = Stop-AzVM -ResourceGroupName $resourceGroupName -Name DC_VM -Force

#>

