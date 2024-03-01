$ErrorActionPreference = 'Stop'

Import-Module -Name PSFramework -Verbose:$false

Write-PSFMessage -Level Verbose -Message 'Importing PowerShell-Modules Az.Accounts, Az.Resources, Az.Network, Az.KeyVault, Az.Compute'
Import-Module -Name Az.Accounts, Az.Resources, Az.Network, Az.KeyVault, Az.Compute -Verbose:$false

Write-PSFMessage -Level Verbose -Message 'Importing PowerShell-Module Posh-SSH'
Import-Module -Name Posh-SSH -MinimumVersion 3.1.3 -Verbose:$false

if (Test-Path -Path $PSScriptRoot\MyAzureLabEnvironment.ps1) {
    Write-PSFMessage -Level Verbose -Message 'Importing local configuration'
    . $PSScriptRoot\MyAzureLabEnvironment.ps1
}

Write-PSFMessage -Level Verbose -Message 'Getting Azure context'
$context = Get-AzContext
if ($context) {
    if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription -and $context.Account.Id -eq $Env:MyAzureAccountId -and $context.Subscription.Name -eq $Env:MyAzureSubscription) {
        Write-PSFMessage -Level Verbose -Message "Already connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
    } elseif ($Env:MyAzureAccountId -and $Env:MyAzureSubscription) {
        Write-PSFMessage -Level Host -Message "Currently connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
        $message = "Switching to account '$($Env:MyAzureAccountId)' and subscription '$($Env:MyAzureSubscription)'"
        if ($Env:MyAzureTenant) {
            $message += " in tenant '$($Env:MyAzureTenant)'"
        }
        Write-PSFMessage -Level Host -Message $message
        $accountParams = @{
            AccountId    = $Env:MyAzureAccountId
            Subscription = $Env:MyAzureSubscription
        }
        if ($Env:MyAzureTenant) {
            $accountParams.Tenant = $Env:MyAzureTenant
        }
        $null = Connect-AzAccount @accountParams
    } else {
        Write-PSFMessage -Level Verbose -Message "Connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
    }
} else {
    if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription) {
        $message = "Connecting to account '$($Env:MyAzureAccountId)' and subscription '$($Env:MyAzureSubscription)'"
        if ($Env:MyAzureTenant) {
            $message += " in tenant '$($Env:MyAzureTenant)'"
        }
        Write-PSFMessage -Level Host -Message $message
        $accountParams = @{
            AccountId    = $Env:MyAzureAccountId
            Subscription = $Env:MyAzureSubscription
        }
        if ($Env:MyAzureTenant) {
            $accountParams.Tenant = $Env:MyAzureTenant
        }
        $null = Connect-AzAccount @accountParams
    } else {
        Stop-PSFFunction -Message 'Not connected to Azure. As $Env:MyAzureAccountId and $Env:MyAzureSubscription are not set, we stop here' -EnableException $true
    }
}


function global:New-MyAzureLabSession {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [int]$Timeout = 600,
        [switch]$EnableException
    )

    if ($ComputerName) {
        $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
        Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
    }

    $vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_VM"
    if ($vm.OSProfile.WindowsConfiguration) {
        $vmIsWindows = $true
        $psSessionParam = @{
            ConnectionUri  = "https://$($IPAddress):5986"
            Credential     = $Credential
            SessionOption  = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            Authentication = "Negotiate"
        }
    } elseif ($vm.OSProfile.LinuxConfiguration) {
        $vmIsLinux = $true
        $sshSessionParam = @{
            ComputerName = $IPAddress
            Credential   = $Credential
            AcceptKey    = $true
        }
    } else {
        Stop-PSFFunction -Message "Unknown operating system for computer name $ComputerName" -EnableException $EnableException
        return
    }

    $waitUntil = (Get-Date).AddSeconds($Timeout)

    Write-PSFMessage -Level Verbose -Message 'Creating Session'
    while ((Get-Date) -lt $waitUntil) {
        try {
            if ($vmIsWindows) {
                New-PSSession @psSessionParam
            } elseif ($vmIsLinux) {
                New-SSHSession @sshSessionParam
            }
            break
        } catch {
            $lastError = $_
            Write-PSFMessage -Level Verbose -Message "Failed with: $lastError"
            Start-Sleep -Seconds 15
        }
    }
    if ((Get-Date) -ge $waitUntil) {
        Stop-PSFFunction -Message "Operation timed out. Last error message: $lastError" -EnableException $EnableException
    }
}

function global:Start-MyAzureLabRDP {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [switch]$EnableException
    )

    process {
        try {
            $ip = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            $user = $Credential.UserName
            $pass = $Credential.GetNetworkCredential().Password
            $null = cmdkey /add:TERMSRV/$ip /user:$user /pass:$pass
            mstsc /v:$ip
            $target = [datetime]::Now.AddSeconds(15)
            while ([datetime]::Now -lt $target) {
                Start-Sleep -Milliseconds 100
                if ((Get-Process -Name mstsc -ErrorAction SilentlyContinue).MainWindowTitle -match "^$ip - ") {
                    break
                }
            }
            $null = cmdkey /delete:TERMSRV/$ip
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function Invoke-MyAzureLabSSHCommand {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [string[]]$Command,
        [int]$TimeOut = 9999,
        [int]$SuccessExitStatus = 0,
        [switch]$ShowOutput,
        [switch]$EnableException
    )
    
    try {
        if ($ComputerName) {
            $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
        }

        $sshSessionParams = @{
            ComputerName  = $IPAddress
            Credential    = $Credential
            Force         = $true
            WarningAction = 'SilentlyContinue'
            ErrorAction   = 'Stop'
        }
        $sshSession = New-SSHSession @sshSessionParams
    } catch {
        Stop-PSFFunction -Message "Error while creating ssh session: $_" -EnableException $EnableException
        return
    }
    
    $returnValue = $true
    foreach ($cmd in $Command) {
        $sshCommandParams = @{
            SSHSession               = $sshSession
#            Command                  = '. ~/.bash_profile && ' + $cmd
            Command                  = $cmd
            EnsureConnection         = $true
            TimeOut                  = $TimeOut
            ShowStandardOutputStream = $ShowOutput
            ShowErrorOutputStream    = $ShowOutput
            ErrorAction              = 'Stop'
        }
        $sshResult = Invoke-SSHCommand @sshCommandParams
        if ($sshResult.ExitStatus -ne $SuccessExitStatus) {
            $returnValue = $false
            break
        }
    }
    $null = $sshSession | Remove-SSHSession
    if ($returnValue -eq $false) {
        Stop-PSFFunction -Message "Command '$cmd' returned with ExitStatus $($sshResult.ExitStatus)" -EnableException $EnableException
    }
}

function Get-MyAzureLabSFTPItem {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [string[]]$Path,
        [string]$Destination,
        [switch]$Force,
        [switch]$EnableException
    )

    try {
        if ($ComputerName) {
            $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
        }

        $sftpSessionParams = @{
            ComputerName  = $IPAddress
            Credential    = $Credential
            Force         = $true
            WarningAction = 'SilentlyContinue'
            ErrorAction   = 'Stop'
        }
        $sftpSession = New-SFTPSession @sftpSessionParams
    } catch {
        Stop-PSFFunction -Message "Error while creating sftp session: $_" -EnableException $EnableException
        return
    }

    try {
        Get-SFTPItem -SFTPSession $sftpSession -Path $Path -Destination $Destination -ErrorAction Stop
    } catch {
        Stop-PSFFunction -Message "Error while running sftp command: $_" -EnableException $EnableException
    } finally {
        $null = $sftpSession | Remove-SFTPSession
    }
}

function Set-MyAzureLabSFTPItem {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [string[]]$Path,
        [string]$Destination,
        [switch]$Force,
        [switch]$EnableException
    )

    try {
        if ($ComputerName) {
            $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
        }

        $sftpSessionParams = @{
            ComputerName  = $IPAddress
            Credential    = $Credential
            Force         = $true
            WarningAction = 'SilentlyContinue'
            ErrorAction   = 'Stop'
        }
        $sftpSession = New-SFTPSession @sftpSessionParams
    } catch {
        Stop-PSFFunction -Message "Error while creating sftp session: $_" -EnableException $EnableException
        return
    }

    try {
        Set-SFTPItem -SFTPSession $sftpSession -Path $Path -Destination $Destination -ErrorAction Stop -Force:$Force 
    } catch {
        Stop-PSFFunction -Message "Error while running sftp command: $_" -EnableException $EnableException
    } finally {
        $null = $sftpSession | Remove-SFTPSession
    }
}

function New-MyAzureLabKeyVault {
    # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/winrm
    # https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate

    [CmdletBinding()]
    Param(
        [PSCredential]$Credential,
        [switch]$EnableException
    )

    process {
        $keyVaultParam = @{
            VaultName                    = "KeyVault$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
            EnabledForDeployment         = $true
            EnabledForTemplateDeployment = $true
            WarningAction                = "SilentlyContinue"  # Suppress warning about future changes
        }
        $certificateName = "$($resourceGroupName)Certificate"
        $certificateFilename = "$env:TEMP\$certificateName.pfx"
        
        try {
            Write-PSFMessage -Level Verbose -Message 'Creating KeyVault'
            $null = New-AzKeyVault -ResourceGroupName $resourceGroupName -Location $location @keyVaultParam

            Write-PSFMessage -Level Verbose -Message 'Creating SelfSignedCertificate'
            $certificate = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation Cert:\CurrentUser\My -KeySpec KeyExchange
    
            Write-PSFMessage -Level Verbose -Message 'Exporting PfxCertificate'
            $null = Export-PfxCertificate -Cert $certificate -FilePath $certificateFilename -Password $Credential.Password
    
            Write-PSFMessage -Level Verbose -Message 'Importing KeyVaultCertificate'
            $null = Import-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName -FilePath $certificateFilename -Password $Credential.Password
        } catch {
            if ($certificate) {
                Write-PSFMessage -Level Verbose -Message 'Removing certificate'
                Remove-Item -Path "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
            }
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        } finally {
            if (Test-Path -Path $certificateFilename) {
                Write-PSFMessage -Level Verbose -Message 'Removing exported PfxCertificate'
                Remove-Item -Path $certificateFilename
            }
        }
    }
}

function New-MyAzureLabNetwork {
    [CmdletBinding()]
    Param(
        [string]$HomeIP,
        [switch]$EnableException
    )

    process {
        if (-not $HomeIP) {
            Write-PSFMessage -Level Warning 'Using 127.0.0.1 for HomeIP - you have to update the network security group to get access to the network'
            $HomeIP = '127.0.0.1'
        }
        
        $virtualNetworkParam = @{
            Name          = "VirtualNetwork"
            AddressPrefix = "10.0.0.0/16"
        }
        $virtualNetworkSubnetConfigParam = @{
            Name          = "Default"
            AddressPrefix = "10.0.0.0/24"
            WarningAction = "SilentlyContinue"  # Suppress warning about future changes
        }
        $networkSecurityGroupParam = @{
            Name = "NetworkSecurityGroup"
        }
        $networkSecurityRules = @(
            @{
                Name                     = "AllowSshFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1000"
                SourceAddressPrefix      = $HomeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 22
                Access                   = "Allow"
            }
            @{
                Name                     = "AllowRdpFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1001"
                SourceAddressPrefix      = $HomeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 3389
                Access                   = "Allow"
            }
            @{
                Name                     = "AllowWinRmFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1002"
                SourceAddressPrefix      = $HomeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 5986
                Access                   = "Allow"
            }
            @{
                Name                     = "Allow8000FromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1003"
                SourceAddressPrefix      = $HomeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 8000
                Access                   = "Allow"
            }
        )

        try {
            Write-PSFMessage -Level Verbose -Message 'Creating VirtualNetworkSubnetConfig'
            $virtualNetworkSubnetConfig = New-AzVirtualNetworkSubnetConfig @virtualNetworkSubnetConfigParam
            
            Write-PSFMessage -Level Verbose -Message 'Creating VirtualNetwork'
            $null = New-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Location $location @virtualNetworkParam -Subnet $virtualNetworkSubnetConfig
            
            $securityRules = foreach ($networkSecurityRuleConfigParam in $networkSecurityRules) {
                Write-PSFMessage -Level Verbose -Message 'Creating NetworkSecurityRuleConfig'
                New-AzNetworkSecurityRuleConfig @networkSecurityRuleConfigParam
            }
            
            Write-PSFMessage -Level Verbose -Message 'Creating NetworkSecurityGroup'
            $null = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Location $location @networkSecurityGroupParam -SecurityRules $securityRules
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function New-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [ValidateSet('WindowsServer2016', 'WindowsServer2019', 'WindowsServer2022', 'Windows10', 'SQLServer2017', 'SQLServer2019', 'SQLServer2022', 'Ubuntu22', 'AlmaLinux8')]
        [string]$SourceImage,
        [string]$VMSize = "Standard_B2s",
        [PSCredential]$Credential,
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message 'Getting key vault and certificate url'
            $keyVault = Get-AzKeyVault -ResourceGroupName $resourceGroupName -WarningAction SilentlyContinue
            $certificateUrl = (Get-AzKeyVaultSecret -VaultName $keyVault.VaultName -Name "$($resourceGroupName)Certificate").Id
    
            Write-PSFMessage -Level Verbose -Message 'Getting subnet, domain controller IP and network security group'
            $subnet = (Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName).Subnets[0]
            $dcPrivateIpAddress = $subnet.AddressPrefix[0].Split('/')[0] -replace '0$', '10'
            $networkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName
        } catch {
            Stop-PSFFunction -Message 'Failed to get information' -ErrorRecord $_ -EnableException $EnableException
            return
        }

        $publicIpAddressParam = @{
            Name             = "$($ComputerName)_PublicIP"
            AllocationMethod = "Static"
            WarningAction    = "SilentlyContinue"
        }
        $networkInterfaceParam = @{
            Name                   = "$($ComputerName)_Interface"
            SubnetId               = $subnet.Id
            NetworkSecurityGroupId = $networkSecurityGroup.Id
        }
        $vmConfigParam = @{
            VMName              = "$($ComputerName)_VM"
            VMSize              = $VMSize                 # Get-AzComputeResourceSku | Where-Object { $_.Locations -contains $location }  https://azureprice.net/
        }
        $secretParam = @{
            SourceVaultId    = $keyVault.ResourceId
            CertificateStore = "My"
            CertificateUrl   = $certificateUrl
        }
        if ($SourceImage -like 'Windows*' -or $SourceImage -like 'SQLServer*') {
            $operatingSystemParam = @{
                ComputerName        = $ComputerName
                Windows             = $true
                Credential          = $Credential
                WinRMHttps          = $true
                WinRMCertificateUrl = $certificateUrl
                ProvisionVMAgent    = $true
            }
        } elseif ($SourceImage -like 'Ubuntu*') {
            $operatingSystemParam = @{
                ComputerName        = $ComputerName
                Linux               = $true
                Credential          = $Credential
            }
        } 
        else {
            Stop-PSFFunction -Message "Unknown operating system for source image $SourceImage" -EnableException $EnableException
            return
        }
        if ($SourceImage -eq 'WindowsServer2016') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsServer"   # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "WindowsServer"            # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "2016-Datacenter"          # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'WindowsServer2019') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsServer"   # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "WindowsServer"            # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "2019-Datacenter"          # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'WindowsServer2022') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsServer"   # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "WindowsServer"            # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "2022-datacenter"          # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'Windows10') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsDesktop"  # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "Windows-10"               # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "win10-22h2-pro"           # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'SQLServer2017') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftSQLServer"       # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "SQL2017-WS2016"           # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "SQLDEV"                   # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'SQLServer2019') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftSQLServer"       # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "sql2019-ws2019"           # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "sqldev"                   # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'SQLServer2022') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftSQLServer"       # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "sql2022-ws2022"           # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "sqldev-gen2"              # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'Ubuntu22') {
            $sourceImageParam = @{
                PublisherName = "Canonical"                     # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like Canonical*
                Offer         = "0001-com-ubuntu-server-jammy"  # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "22_04-lts-gen2"                # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } elseif ($SourceImage -eq 'AlmaLinux8') {
            $sourceImageParam = @{
                PublisherName = "almalinux"                     # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like alma*
                Offer         = "almalinux-x86_64"              # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "8-gen2"                        # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
                Version       = "latest"
            }
        } else {
            Stop-PSFFunction -Message "Unknown image parameters for source image $SourceImage" -EnableException $EnableException
            return
        }
        $osDiskParam = @{
            Name         = "$($ComputerName)_Disk1.vhd"
            CreateOption = "FromImage"
        }
        $bootDiagnosticParam = @{
            Disable = $true
        }
        if ($ComputerName -eq 'DC') {
            $networkInterfaceParam.PrivateIpAddress = $dcPrivateIpAddress
        }

        try {
            Write-PSFMessage -Level Verbose -Message 'Creating PublicIpAddress'
            $publicIpAddress = New-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Location $location @publicIpAddressParam

            Write-PSFMessage -Level Verbose -Message 'Creating NetworkInterface'
            $networkInterface = New-AzNetworkInterface -ResourceGroupName $resourceGroupName -Location $location @networkInterfaceParam -PublicIpAddressId $publicIpAddress.Id

            Write-PSFMessage -Level Verbose -Message 'Creating VMConfig'
            $vmConfig = New-AzVMConfig @vmConfigParam

            Write-PSFMessage -Level Verbose -Message 'Adding NetworkInterface'
            $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $networkInterface.Id

            Write-PSFMessage -Level Verbose -Message 'Setting OperatingSystem'
            $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig @operatingSystemParam

            Write-PSFMessage -Level Verbose -Message 'Setting SourceImage'
            $vmConfig = Set-AzVMSourceImage -VM $vmConfig @sourceImageParam

            Write-PSFMessage -Level Verbose -Message 'Setting OSDisk'
            $vmConfig = Set-AzVMOSDisk -VM $vmConfig @osDiskParam

            Write-PSFMessage -Level Verbose -Message 'Setting BootDiagnostic'
            $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig @bootDiagnosticParam

            if ($SourceImage -like 'Windows*' -or $SourceImage -like 'SQLServer*') {
                Write-PSFMessage -Level Verbose -Message 'Adding Secret'
                $vmConfig = Add-AzVMSecret -VM $vmConfig @secretParam
            }

            Write-PSFMessage -Level Verbose -Message 'Creating VM'
            $result = New-AzVM -ResourceGroupName $resourceGroupName -Location $location -VM $vmConfig -WarningAction SilentlyContinue 6> $null  # Suppress warning about future changes / Suppress info about Azure Trusted Launch VMs
            Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function Remove-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message "Removing virtual maschine $ComputerName"
            $null = Remove-AzVM -Name "$($ComputerName)_VM" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzDisk -DiskName "$($ComputerName)_Disk1.vhd" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzNetworkInterface -Name "$($ComputerName)_Interface" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzPublicIpAddress -Name "$($ComputerName)_PublicIP" -ResourceGroupName $resourceGroupName -Force
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function Invoke-MyAzureLabPart1 {
    [CmdletBinding()]
    Param (
        [hashtable]$Config,
        [switch]$EnableException
    )

    process {
        try {
            ##########
            Write-PSFMessage -Level Host -Message 'Part 1: Setting up the virtual maschines'
            ##########

            #####
            Write-PSFMessage -Level Host -Message 'Step 1: Setting up main infrastructure'
            #####

            # Stop if resource group exists
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Stop-PSFFunction -Message "Resource group $resourceGroupName already exists. Stopping."
            }

            Write-PSFMessage -Level Host -Message 'Getting HomeIP'
            $homeIP = (Invoke-WebRequest -uri "http://ifconfig.me/ip" -UseBasicParsing).Content
            if ($homeIP -notmatch '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
                Stop-PSFFunction -Message 'Failed to get IPv4 home IP. Stopping.' -Target $homeIP -EnableException $EnableException
            }

            Write-PSFMessage -Level Host -Message "Creating resource group $resourceGroupName"
            $null = New-AzResourceGroup -Name $resourceGroupName -Location $location

            Write-PSFMessage -Level Host -Message 'Creating key vault and certificate'
            New-MyAzureLabKeyVault -Credential $initCredential

            Write-PSFMessage -Level Host -Message 'Creating network and security group'
            New-MyAzureLabNetwork -HomeIP $homeIP

            #####
            Write-PSFMessage -Level Host -Message 'Step 2: Setting up virtual maschines'
            #####

            # See https://azureprice.net/ to get a suitable vm size 

            # In case something fails and a maschine needs to be rebuild:
            # Remove-MyAzureLabVM -ComputerName WINDC01

            Write-PSFMessage -Level Host -Message 'Creating virtual maschine STATUS'
            New-MyAzureLabVM -ComputerName STATUS -SourceImage Ubuntu22 -VMSize Standard_B2ms -Credential $initCredential

            foreach ($computerName in $Config.Keys) {
                Write-PSFMessage -Level Host -Message "Creating virtual maschine $computerName"
                New-MyAzureLabVM -ComputerName $computerName -SourceImage $config.$computerName.SourceImage -VMSize $config.$computerName.VMSize -Credential $initCredential
            }

            #####
            Write-PSFMessage -Level Host -Message 'Step 3: Setting up deployment monitoring'
            #####

            Set-MyAzureLabSFTPItem -ComputerName STATUS -Credential $initCredential -Path $PSScriptRoot\status.py, $PSScriptRoot\status.html -Destination "/home/$($initCredential.UserName)" -Force
            $installStatusApi = @(
                'sudo apt-get update'
                'sudo apt-get install -y python3-pip'
                'pip install -q fastapi "uvicorn[standard]"'
                "echo '@reboot /usr/bin/python3 /home/$($initCredential.UserName)/status.py &' > /tmp/crontab"
                'crontab /tmp/crontab'
                'rm /tmp/crontab'
            )
            Invoke-MyAzureLabSSHCommand -ComputerName STATUS -Credential $initCredential -Command $installStatusApi
            $result = Restart-AzVM -ResourceGroupName $resourceGroupName -Name STATUS_VM
            if ($result.Status -ne 'Succeeded') {
                Stop-PSFFunction -Message 'Restart failed' -Target $result -EnableException $EnableException
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function Invoke-MyAzureLabDeployment {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$Path,
        [PSCustomObject]$Config,
        [scriptblock]$ScriptBlock,
        [switch]$EnableException
    )

    process {
        try {
            $session = New-MyAzureLabSession -ComputerName $ComputerName -Credential $Credential
            $commandParams = @{
                Session = $session
            }

            if ($Path) {
                $script = Get-Content -Path $Path -Encoding UTF8 -Raw
                $commandParams.ArgumentList = $script, $Config
                $commandParams.ScriptBlock = {
                    Param(
                        [string]$Script,
                        [PSCustomObject]$Config
                    )
    
                    $ErrorActionPreference = 'Stop'
    
                    if (-not (Test-Path -Path C:\Deployment)) {
                        $null = New-Item -Path C:\Deployment -ItemType Directory
                    }
                    Set-Content -Path C:\Deployment\deployment.ps1 -Value $Script -Encoding UTF8
                    Set-Content -Path C:\Deployment\config.txt -Value ($Config | ConvertTo-Json -Depth 99) -Encoding UTF8
    
                    if ((Get-ScheduledTask).TaskName -notcontains 'DeploymentAtStartup') {
                        $scheduledTaskActionParams = @{
                            Execute  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                            Argument = '-ExecutionPolicy RemoteSigned -NonInteractive -File C:\Deployment\deployment.ps1'
                        }
                        $scheduledTaskParams = @{
                            TaskName = 'DeploymentAtStartup'
                            Trigger  = New-ScheduledTaskTrigger -AtStartup
                            User     = 'SYSTEM'
                            Action   = New-ScheduledTaskAction @scheduledTaskActionParams
                        }
                        $null = Register-ScheduledTask @scheduledTaskParams
                    }
    
                    Start-ScheduledTask -TaskName DeploymentAtStartup
                }
            } elseif ($ScriptBlock) {
                $commandParams.ScriptBlock = $ScriptBlock
            }

            Write-PSFMessage -Level Verbose -Message "Starting Invoke-Command"
            Invoke-Command @commandParams
            Write-PSFMessage -Level Verbose -Message "Finished Invoke-Command"
            $session | Remove-PSSession
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function Wait-MyAzureLabDeploymentCompletion {
    [CmdletBinding()]
    Param (
        [string]$WaitFor = 'Finished deployment',
        [datetime]$OnlyStatusAfter = [datetime]::Now,
        [switch]$EnableException
    )

    process {
        try {
            $statusApiPublicIP = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "STATUS_PublicIP").IpAddress
            while (1) {
                $data = (Invoke-WebRequest -Uri "http://$($statusApiPublicIP):8000/status").Content | ConvertFrom-Json
                $data = $data | Where-Object { [datetime]$_.Time -gt $OnlyStatusAfter }  
                Clear-Host
                Write-Host "Results from http://$($statusApiPublicIP):8000"
                $data | Sort-Object Time | Format-Table -Property IP, Host, Time, Message -Wrap
                if ($WaitFor -eq ($data.Message | Select-Object -Unique)) {
                    break
                }
                Start-Sleep -Seconds 10
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function global:Start-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Starting VMs in resource group $resourceGroupName."
                $jobs = foreach ($vm in Get-AzVM -ResourceGroupName $resourceGroupName) {
                    Write-PSFMessage -Level Verbose -Message "Starting $($vm.Name)"
                    Start-Job -ScriptBlock {
                        $using:vm | Start-AzVM
                    }
                }
                $null = Wait-Job -Job $jobs
                $result = Receive-Job -Job $jobs
                if ($result.Status -ne 'Succeeded') {
                    $result | Format-Table
                    Stop-PSFFunction -Message "Start failed for at least one VM" -Target $result
                } else {
                    Get-AzVM -ResourceGroupName $resourceGroupName -Status | Format-Table -Property Name, PowerState
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function global:Stop-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Stopping VMs in resource group $resourceGroupName."
                $jobs = foreach ($vm in Get-AzVM -ResourceGroupName $resourceGroupName) {
                    Write-PSFMessage -Level Verbose -Message "Stopping $($vm.Name)"
                    Start-Job -ScriptBlock {
                        $using:vm | Stop-AzVM -Force
                    }
                }
                $null = Wait-Job -Job $jobs
                $result = Receive-Job -Job $jobs
                if ($result.Status -ne 'Succeeded') {
                    $result | Format-Table
                    Stop-PSFFunction -Message "Stop failed for at least one VM" -Target $result
                } else {
                    Get-AzVM -ResourceGroupName $resourceGroupName -Status | Format-Table -Property Name, PowerState
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

function global:Remove-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Removing resource group $resourceGroupName, key vault and certificate"
                $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
                Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
                Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object Subject -eq "CN=$($resourceGroupName)Certificate" | Remove-Item
            } else {
                Write-PSFMessage -Level Host -Message "ResourceGroup $resourceGroupName not found"
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

