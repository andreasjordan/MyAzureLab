# MyAzureLab

This repository helps me to setup lab environments in Azure based on PowerShell scripts.

Most people would do this with Terraform or OpenTofu and Ansible. And yes, these programms have a lot of advantages. But I like the flexibility of PowerShell scripts as I can run only part of them and so build different labs with the same set of scripts.


## lib folder

This folder mainly contains all of the code of my own functions (...-MyAzureLab...) that interact with the used PowerShell modules like Az or Posh-SSH.


## MyAzureLab.ps1

This script imports the needed PowerShell modules, connects to Azure and imports all of my own functions from the lib folder.

This script must be imported inside of the "init_..." scripts.


## MyAzureLabEnvironment.ps1

This holds environment variables with my personl settings. That's why it's part of .gitignore and you have to setup this file on your local system with this content:

Mandatory:

```
$Env:MyAzureAccountId    = 'my@mydom.com'
$Env:MyAzureSubscription = 'The name of the subscription'
```

Optional:

```
# Just needed if your account is linked to multiple tenants and you get "WARNUNG: Unable to acquire token for tenant ..."
$Env:MyAzureTenant = '12345678-abcd-abcd-abcd-012345678901' 

# I have a permanent server with the status api. If this variable is empty, a separate vm for the status api will be deployed.
$Env:MyStatusURL = 'https://your-server-with-the-status-api/status'

# Just needed for labs where I want to test the installation with the RTM version.
$Env:MySQL2022URL = 'https://www.dropbox.com/secret-part-of-the-url/enu_sql_server_2022_developer_edition_x64_dvd_7cacf733.iso?dl=1'
$Env:MySQL2019URL = 'https://www.dropbox.com/secret-part-of-the-url/en_sql_server_2019_developer_x64_dvd_e5ade34a.iso?dl=1'

# Just needed for labs where I need oracle instances.
$Env:MyOracleLinuxDbHomeURL         = 'https://www.dropbox.com/secret-part-of-the-url/LINUX.X64_193000_db_home.zip?dl=1'
$Env:MyOracleWindowsClientHomeURL   = 'https://www.dropbox.com/secret-part-of-the-url/WINDOWS.X64_193000_client_home.zip?dl=1'
$Env:MyOracleWindowsSqlDeveloperURL = 'https://www.dropbox.com/secret-part-of-the-url/sqldeveloper-22.2.1.234.1810-x64.zip?dl=1'
```

This file is imported by MyAzureLab.ps1 just before connecting to Azure.


## init_... scripts

These scripts contain the code to setup a lab and to work with a lab.

The scripts include a break statement, so only the first part is executed and the rest of the code should be executed line by line. So the code is like a menu to choose from.

You should run these scripts with `. .\init_XYZ.ps1` from the main folder to include all the variables they set into the currect session.


### init_JustForFun.ps1

This script is like a blueprint for your own project. And it is also a good way to test, if you have all the requirements set up correctly.


### init_SQLServerLab.ps1

This script creates a complex environment with an AD infrastructure and multiple SQL Servers.

The individual code for the deployment is saved in the folder SQLServerLab.


### init_SQLServerLabMini.ps1

This script creates a simple environment with an AD infrastructure and only a single SQL Server and a client. 

The individual code for the deployment is saved in the folder SQLServerLabMini.

This lab is intended to test and to show specific behavior of the PowerShell module dbatools. If you can setup this lab and reproduce a dbatools bug inside of the lab, then I have a perfect environment to work on a fix.

#### Some commands for the CLIENT to get used to the lab and dbatools:

```
Import-Module -Name dbatools

# Let's fill some variables (accounts based on "https://github.com/andreasjordan/MyAzureLab/blob/main/SQLServerLabMini/set_vm_config.ps1"):
$computerName = 'SQL2022'
$domAdminCredential = [PSCredential]::new('DOM\Admin', (ConvertTo-SecureString -String 'P#ssw0rd' -AsPlainText -Force))
$sqlAdminCredential = [PSCredential]::new('DOM\SQLAdmin', (ConvertTo-SecureString -String 'P#ssw0rd' -AsPlainText -Force))

# Let's see what instances are installed on the SQL2022:
Find-DbaInstance -ComputerName $computerName

# "Availability" is "Unknown" as we are a normal user.
# Let's run it again as domain admin:
Find-DbaInstance -ComputerName $computerName -Credential $domAdminCredential

# The standard instance is "Unavailable".
# Let's see what the service status is:
Get-DbaService -ComputerName $computerName -Credential $domAdminCredential -Type Engine | Format-Table

# TODO: The StartMode of the default instance is currently Automatic, but I think it was Manual last time. Will check that again.

# The State is Stopped, because the script stopped it. 
# Let's start it again:
Start-DbaService -ComputerName $computerName -Credential $domAdminCredential -InstanceName MSSQLSERVER -Type Engine

# ERROR: 
# WARNING: [19:13:53][Get-DbaCmObject] [sql2022.dom.local] Invalid connection credentials
# WARNING: [19:13:53][Update-ServiceStatus] Failed to retrieve service name MSSQLSERVER from the CIM object collection - the service will not be processed

# Run this command in a PowerShell started as DOM\Admin:
# Start-DbaService -ComputerName SQL2022 -InstanceName MSSQLSERVER -Type Engine

# Let's try to connect:
$sqlInstance = (Find-DbaInstance -ComputerName $computerName).SqlInstance
$server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $sqlAdminCredential
$server | Format-Table

# Let's show the databases:
Get-DbaDatabase -SqlInstance $server | Format-Table -AutoSize
```


### init_DockerDatabases.ps1

This script will setup my lab with Azure virtual maschines for a database environment based on docker.

It uses code from my repos [PowerShell-for-DBAs](..\PowerShell-for-DBAs\README.md) and [PowerShell-moves-Data-around](..\PowerShell-moves-Data-around\README.md).


## Security in the SQL Server Labs

* DOM\Admin is the Domain Admin
* DOM\User is just a Domain User that can RDP to the CLIENT
* DOM\SQLAdmin is the SQL Server Admin that is also local Windows Admin on SQLxxxx and can RDP to the CLIENT
* DOM\SQLUser is a test user for non-admin access to SQL Server and can RDP to the CLIENT
