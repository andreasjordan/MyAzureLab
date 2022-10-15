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

This Skript will start SQL Server images, mount the data disk and copy the source files to the data disk.
That way I can use the SQL Server sources with normal Windows Servers and install SQL Server instances there.

It takes about 10 minutes per SQL Server version and some additional minutes for the infratructure.

It will connect to Azure with
* a given acount name (`$accountId`)
* a given subscription (`$subscriptionName`)

It will use a [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell) with
* a given name (`$resourceGroupName`)
* in a given location (`$location`)

It will temporarily create a [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts) with
* the name "KeyVault<10 digit random number>"
* a self signed certificate named "<name of resource group>Certificate" to support connecting to the virtual maschines via WinRM

It will temporarily create a [virtual network](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) with
* the name "VirtualNetwork"
* the address prefix "10.0.0.0/16"
* a subnet with the name "Default" and the address prefix "10.0.0.0/24"
* the IP address "10.0.0.10" for the domain controller

It will temporarily create a [network security group](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) with
* the name "NetworkSecurityGroup"
* rules to allow communication from my home address to the network for RDP (port 3389), SSH (port 22) and WinRM (port 5986)

It will temporarily create a set of [virtual maschines](https://docs.microsoft.com/en-us/azure/virtual-machines/) and
* mount the data disk
* copy the SQL Server sources
* unmount the data disk
* removes the virtual maschine

It will then remove the key vault and the network

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
$resourceGroupName = 'DataDisk'
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



# Part 2: Setting up some infrastructure

Write-PSFMessage -Level Host -Message 'Creating key vault and certificate'
New-MyAzureLabKeyVault

Write-PSFMessage -Level Host -Message 'Creating network and security group'
New-MyAzureLabNetwork



# Part 3: Setting up virtual maschines and copying the SQL Server source files

foreach ($version in '2019') {
    # $version = '2017'

    # In case I need to recreate: Remove-MyAzureLabVM -ComputerName SQL$version
    Write-PSFMessage -Level Host -Message "Creating virtual maschine SQL$version"
    New-MyAzureLabVM -ComputerName SQL$version -SourceImage SQLServer$version -NoDomain

    Write-PSFMessage -Level Host -Message "Mounting data disk to virtual maschine SQL$version"
    $vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name SQL$($version)_VM
    $dataDisk = Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName datadisk
    $vm = Add-AzVMDataDisk -VM $vm -Name datadisk -CreateOption Attach -ManagedDiskId $dataDisk.Id -Lun 1
    $result = Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm
    Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

    Write-PSFMessage -Level Host -Message "Copying SQL Server source files to data disk"
    $psSession = New-MyAzureLabSession -ComputerName SQL$version -Credential $credential
    Invoke-Command -Session $psSession -ArgumentList $version -ScriptBlock { 
        param([string]$version)
        $ErrorActionPreference = 'Stop'
        Get-Partition -Volume (Get-Volume -FileSystemLabel Daten) | Set-Partition -NewDriveLetter S
        $null = New-Item -Path S:\Software\SQLServer$version -ItemType Directory
        Copy-Item -Path C:\SQLServerFull\* -Destination S:\Software\SQLServer$version -Recurse   
    }
    $psSession | Remove-PSSession

    Write-PSFMessage -Level Host -Message "Unmounting data disk from virtual maschine SQL$version"
    $vm = Remove-AzVMDataDisk -VM $vm -DataDiskNames datadisk 
    $result = Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm
    Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

    Write-PSFMessage -Level Host -Message "Removing virtual maschine SQL$version"
    Remove-MyAzureLabVM -ComputerName "SQL$version"
}



# Part 4: Removing the infrastructure

Write-PSFMessage -Level Host -Message 'Removing network and security group'
Remove-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name VirtualNetwork -Force
Remove-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup -Force

Write-PSFMessage -Level Host -Message 'Removing key vault and certificate'
Get-AzKeyVault -ResourceGroupName $resourceGroupName -WarningAction SilentlyContinue | Remove-AzKeyVault -Force
Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object Subject -eq "CN=$($resourceGroupName)Certificate" | Remove-Item


Write-PSFMessage -Level Host -Message 'Finished'
