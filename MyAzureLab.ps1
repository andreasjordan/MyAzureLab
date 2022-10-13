function New-MyAzureLabSession {
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
            Write-PSFMessage -Level Verbose -Message "Failed with: $_"
            Start-Sleep -Seconds 15
        }
    }
    if ((Get-Date) -ge $waitUntil) {
        Stop-PSFFunction -Message 'Failed' -EnableException $EnableException
    }
}



function New-MyAzureLabKeyVault {
    # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/winrm
    # https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate

    [CmdletBinding()]
    Param(
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
            $null = Export-PfxCertificate -Cert $certificate -FilePath $certificateFilename -Password $credential.Password
    
            Write-PSFMessage -Level Verbose -Message 'Importing KeyVaultCertificate'
            $null = Import-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName -FilePath $certificateFilename -Password $credential.Password
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
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message 'Getting home IP'
            $homeIP = (Invoke-WebRequest -uri "http://ifconfig.me/ip" -UseBasicParsing).Content
            Write-PSFMessage -Level Verbose -Message "Using '$homeIP' as home IP"
        } catch {
            Stop-PSFFunction -Message 'Failed to get home IP' -ErrorRecord $_ -EnableException $EnableException
            Write-PSFMessage -Level Warning 'Using 127.0.0.1 for now - you have to update the network security group to get access to the network'
            $homeIP = '127.0.0.1'
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
                Name                     = "AllowRdpFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1000"
                SourceAddressPrefix      = $homeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 3389
                Access                   = "Allow"
            },
            @{
                Name                     = "AllowSshFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1001"
                SourceAddressPrefix      = $homeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 22
                Access                   = "Allow"
            },
            @{
                Name                     = "AllowWinRmFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1002"
                SourceAddressPrefix      = $homeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 5986
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
    param (
        [string]$ComputerName,
        [ValidateSet('WindowsServer2016', 'WindowsServer2019', 'Windows10', 'SQLServer2017', 'SQLServer2019', 'Ubuntu22')]
        [string]$SourceImage,
        [string]$VMSize = "Standard_B2s",
        [string]$OrganizationalUnit,
        [ScriptBlock]$ScriptBlock,
        [switch]$NoDomain,
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
            AllocationMethod = "Dynamic"
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
                Credential          = $credential
                WinRMHttps          = $true
                WinRMCertificateUrl = $certificateUrl
                ProvisionVMAgent    = $true
            }
        } elseif ($SourceImage -like 'Ubuntu*') {
            $operatingSystemParam = @{
                ComputerName        = $ComputerName
                Linux               = $true
                Credential          = $credential
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
        } elseif ($SourceImage -eq 'Windows10') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsDesktop"  # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "Windows-10"               # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "win10-21h2-pro"           # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
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
        } elseif ($SourceImage -eq 'Ubuntu22') {
            $sourceImageParam = @{
                PublisherName = "Canonical"                     # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like Canonical*
                Offer         = "0001-com-ubuntu-server-jammy"  # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "22_04-lts-gen2"                # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
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
            $result = New-AzVM -ResourceGroupName $resourceGroupName -Location $location -VM $vmConfig
            Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

            if ($SourceImage -like 'Windows*' -or $SourceImage -like 'SQLServer*') {
                Write-PSFMessage -Level Verbose -Message 'Creating PSSession'
                $session = New-MyAzureLabSession -ComputerName $ComputerName -Credential $credential -EnableException
            } elseif ($SourceImage -like 'Ubuntu*') {
                Write-PSFMessage -Level Verbose -Message 'Creating SSHSession'

            }

            if ($NoDomain) {
                Write-PSFMessage -Level Verbose -Message "Skipping Domain configuration"
            } elseif ($ComputerName -eq 'DC') {
                Write-PSFMessage -Level Verbose -Message 'Creating Domain'
                Invoke-Command -Session $session -ArgumentList $domainConfiguration.DomainName, $credential -ScriptBlock {
                    Param([string]$DomainName, [PSCredential]$Credential)
                    $null = Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
                    $forestParam = @{
                        DomainName                    = $DomainName
                        DomainNetbiosName             = $DomainName.Split('.')[0].ToUpper()
                        SafeModeAdministratorPassword = $Credential.Password
                        DomainMode                    = 'def'
                        ForestMode                    = 'WinThreshold'
                        InstallDns                    = $true
                        CreateDnsDelegation           = $false
                        SysvolPath                    = 'C:\Windows\SYSVOL'
                        DatabasePath                  = 'C:\Windows\NTDS'
                        LogPath                       = 'C:\Windows\NTDS'
                        Force                         = $true
                        WarningAction                 = 'SilentlyContinue'
                    }
                    $ProgressPreference = 'SilentlyContinue'
                    $null = Install-ADDSForest @forestParam
                }
            } elseif (-not $NoDomain) {
                Write-PSFMessage -Level Verbose -Message 'Joining Domain'
                $ouPath = $null
                if ($OrganizationalUnit) {
                    $ouPath = "OU=$OrganizationalUnit,DC=$($domainConfiguration.DomainName.Replace('.',',DC='))"
                }
                Write-PSFMessage -Level Verbose -Message "Joining Domain with OUPath '$ouPath'"
                Invoke-Command -Session $session -ArgumentList $domainConfiguration.DomainName, $dcPrivateIpAddress, $domainCredential, $ouPath -ScriptBlock {
                    Param([string]$DomainName, [string]$DomainControllerIP, [PSCredential]$DomainAdminCredential, [string]$OUPath)
                    Set-DnsClientServerAddress -InterfaceIndex ((Get-NetIPConfiguration).InterfaceIndex) -ServerAddresses $DomainControllerIP
                    $addComputerParam = @{
                        DomainName    = $DomainName
                        Server        = "DC.$DomainName"
                        Credential    = $DomainAdminCredential
                        WarningAction = 'SilentlyContinue'
                    }
                    if ($OUPath) {
                        $addComputerParam.OUPath = $OUPath
                    }
                    Add-Computer @addComputerParam
                    Restart-Computer -Force
                }
            }

            if (-not $NoDomain) {
                $session | Remove-PSSession

                Write-PSFMessage -Level Verbose -Message "Waitung for 2 Minutes"
                Start-Sleep -Seconds 120

                Write-PSFMessage -Level Verbose -Message 'Creating PSSession'
                $session = New-MyAzureLabSession -ComputerName $ComputerName -Credential $domainCredential -EnableException
            }

            if ($SourceImage -like 'Windows*' -or $SourceImage -like 'SQLServer*') {
                $fullComputerName = Invoke-Command -Session $session -ScriptBlock { "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }
                Write-PSFMessage -Level Verbose -Message "Full computer name is now '$fullComputerName'"
            }

            if ($ComputerName -eq 'DC') {
                Write-PSFMessage -Level Verbose -Message "Waiting until domain is fully created"
                $waitUntil = (Get-Date).AddSeconds(600)
                while ((Get-Date) -lt $waitUntil) {
                    try {
                        $defaultNamingContext = Invoke-Command -Session $session -ScriptBlock { (Get-ADRootDSE).defaultNamingContext }
                        Write-PSFMessage -Level Verbose -Message "Received default naming context '$defaultNamingContext'"
                        break
                    } catch {
                        Write-PSFMessage -Level Verbose -Message "Failed with: $_"
                        Start-Sleep -Seconds 15
                    }
                }
                if ((Get-Date) -ge $waitUntil) {
                    Stop-PSFFunction -Message 'Failed' -EnableException $EnableException
                }

                Write-PSFMessage -Level Verbose -Message "Creating organizational units, users and groups"
                Invoke-Command -Session $session -ArgumentList $domainConfiguration -ScriptBlock {
                    Param([hashtable]$Config)
                    $pw = ConvertTo-SecureString -String $Config.Password -AsPlainText -Force
                    foreach ($ou in $Config.OUs) {
                        $ouPath = (New-ADOrganizationalUnit -Name $ou.Name -PassThru).DistinguishedName
                        foreach ($user in $ou.Users) {
                            New-ADUser -Name $user -AccountPassword $pw -Enabled $true -Path $ouPath
                        }
                        foreach ($group in $ou.Groups) {
                            New-ADGroup -Name $group.Name -GroupCategory Security -GroupScope Global -Path $ouPath
                            foreach ($user in $group.Members) {
                                New-ADUser -Name $user -AccountPassword $pw -Enabled $true -Path $ouPath
                                Add-ADGroupMember -Identity $group.Name -Members $user
                            }
                            # Add the InitialAdmin as well to the group Admins
                            if ($group.Name -eq 'Admins') {
                                Add-ADGroupMember -Identity $group.Name -Members $Config.InitialAdmin
                            }
                        }
                    }
                    foreach ($gm in $Config.GroupMembers) {
                        Add-ADGroupMember -Identity $gm.Group -Members $gm.Members
                    }
                }

                Write-PSFMessage -Level Verbose -Message "Downloading lab resources from GitHub"
                Invoke-Command -Session $session -ScriptBlock {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri "https://github.com/andreasjordan/demos/archive/test.zip" -OutFile D:\demos.zip
                    Expand-Archive -Path D:\demos.zip -DestinationPath D:\
                }

                Write-PSFMessage -Level Verbose -Message "Restoring GPOs"
                Invoke-Command -Session $session -ScriptBlock {
                    Set-Location -Path D:\demos-*\LabResources\GPO
                    foreach ($gpoFolder in Get-ChildItem -Filter GPO_*) {
                        $id = (Get-ChildItem -Path $gpoFolder.FullName -Filter '{*').Name
                        $null = New-GPO -Name $gpoFolder.Name
                        $null = Import-GPO -TargetName $gpoFolder.Name -Path $gpoFolder.FullName -BackupId $id
                        $null = New-GPLink -Name $gpoFolder.Name -Target (Get-ADRootDSE).defaultNamingContext
                    }
                }

                Write-PSFMessage -Level Verbose -Message "Setting up file server"
                Invoke-Command -Session $session -ScriptBlock {
                    Set-Location -Path D:\demos-*\LabResources\
                    Move-Item -Path .\FileServer -Destination C:\
                    $smbShareAccessParam = @{
                        AccountName = "$env:USERDOMAIN\Admins"
                        AccessRight = 'Full'
                        Force       = $true
                    }
                    $null = New-SmbShare -Path C:\FileServer -Name FileServer | Grant-SmbShareAccess @smbShareAccessParam
                    $null = New-SmbShare -Path C:\FileServer\Backup -Name Backup | Grant-SmbShareAccess @smbShareAccessParam
                    $null = New-SmbShare -Path C:\FileServer\SampleDatabases -Name SampleDatabases | Grant-SmbShareAccess @smbShareAccessParam
                    $null = New-SmbShare -Path C:\FileServer\Software -Name Software | Grant-SmbShareAccess @smbShareAccessParam
                    $null = Grant-SmbShareAccess -Name Backup -AccountName "$env:USERDOMAIN\SQLServiceAccounts" -AccessRight Change -Force

                    Add-DnsServerResourceRecordCName -ZoneName $env:USERDNSDOMAIN -HostNameAlias "$env:COMPUTERNAME.$env:USERDNSDOMAIN" -Name fs
                }
            }

            if ($ScriptBlock) {
                Write-PSFMessage -Level Verbose -Message "Executing script block"
                Invoke-Command -Session $session -ScriptBlock $ScriptBlock
            }

            if ($SourceImage -like 'Windows*' -or $SourceImage -like 'SQLServer*') {
                $session | Remove-PSSession
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}



function Remove-MyAzureLabVM {
    [CmdletBinding()]
    param (
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

            # TODO: Remove computer account from AD
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}



function Add-MyAzureLabSQLSources {
    [CmdletBinding()]
    param (
        [ValidateSet('2017', '2019')]
        [string[]]$Version,
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message 'Creating session to DC'
            $session = New-MyAzureLabSession -ComputerName DC -Credential $domainCredential -EnableException

            foreach ($ver in $version) {
                Write-PSFMessage -Level Verbose -Message "Creating virtual maschine SQL$ver"
                New-MyAzureLabVM -ComputerName "SQL$ver" -SourceImage "SQLServer$ver" -EnableException

                Write-PSFMessage -Level Verbose -Message 'Configuring CredSSP'
                Invoke-Command -Session $session -ArgumentList "SQL$ver.$($domainConfiguration.DomainName)" -ScriptBlock {
                    Param([String]$DelegateComputer)
                    $null = Enable-WSManCredSSP -DelegateComputer $DelegateComputer -Role Client -Force
                }

                Write-PSFMessage -Level Verbose -Message 'Testing CredSSP'
                $waitUntil = (Get-Date).AddSeconds(300)
                while ((Get-Date) -lt $waitUntil) {
                    try {
                        Invoke-Command -Session $session -ArgumentList "SQL$ver.$($domainConfiguration.DomainName)", $domainCredential -ScriptBlock {
                            Param([String]$ComputerName, [PSCredential]$Credential)
                            $sessionParam = @{
                                Authentication = 'Credssp'
                                Credential     = $Credential
                                UseSSL         = $true
                                SessionOption  = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                            }
                            $session = New-PSSession -ComputerName $ComputerName @sessionParam
                        }
                        break
                    } catch {
                        Write-PSFMessage -Level Verbose -Message "Failed with: $_"
                        Start-Sleep -Seconds 15
                    }
                }
                if ((Get-Date) -ge $waitUntil) {
                    Stop-PSFFunction -Message 'Failed to test CredSSP' -EnableException $true
                }

                Write-PSFMessage -Level Verbose -Message 'Using CredSSP to copy SQL Server sources'
                Invoke-Command -Session $session -ScriptBlock {
                    Invoke-Command -Session $session -ScriptBlock {
                        $version = $env:COMPUTERNAME.Substring(3,4)
                        Remove-Item -Path "\\FS\Software\SQLServer\ISO\SQLServer$version\README.md"
                        Copy-Item -Path C:\SQLServerFull\* -Destination "\\FS\Software\SQLServer\ISO\SQLServer$version" -Recurse 
                    }
                }

                Write-PSFMessage -Level Verbose -Message 'Closing session and disabling CredSSP'
                Invoke-Command -Session $session -ScriptBlock {
                    Get-PSSession | Remove-PSSession
                    Disable-WSManCredSSP -Role Client
                }

                Write-PSFMessage -Level Verbose -Message "Removing virtual maschine SQL$Version"
                Remove-MyAzureLabVM -ComputerName "SQL$ver" -EnableException
            }

            Write-PSFMessage -Level Verbose -Message 'Downloading SQL Server sample databases'
            Invoke-Command -Session $session -ScriptBlock {
                # We need to use DC as file server hostname because we don't have CredSSP and must use local hostname
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2019.bak -OutFile \\DC\SampleDatabases\AdventureWorks2019.bak
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2017.bak -OutFile \\DC\SampleDatabases\AdventureWorks2017.bak
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2016.bak -OutFile \\DC\SampleDatabases\AdventureWorks2016.bak
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2014.bak -OutFile \\DC\SampleDatabases\AdventureWorks2014.bak
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/adventureworks/AdventureWorks2012.bak -OutFile \\DC\SampleDatabases\AdventureWorks2012.bak
                Invoke-WebRequest -Uri https://github.com/Microsoft/sql-server-samples/releases/download/wide-world-importers-v1.0/WideWorldImporters-Full.bak -OutFile \\DC\SampleDatabases\WideWorldImporters-Full.bak
            }

            Write-PSFMessage -Level Verbose -Message 'Installing dbatools and downloading SQL Server cumulative updates'
            Invoke-Command -Session $session -ScriptBlock {
                $null = Install-PackageProvider -Name Nuget -Force
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module -Name dbatools
                # We need to use DC as file server hostname because we don't have CredSSP and must use local hostname
                Invoke-WebRequest -Uri https://raw.githubusercontent.com/andreasjordan/demos/master/dbatools/Get-CU.ps1 -OutFile \\DC\Software\SQLServer\CU\Get-CU.ps1
                \\DC\Software\SQLServer\CU\Get-CU.ps1 -Version 2017, 2019 -Path \\DC\Software\SQLServer\CU | Out-Null
            }

            $session | Remove-PSSession
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}

