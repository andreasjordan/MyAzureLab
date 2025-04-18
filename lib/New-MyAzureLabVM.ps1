function New-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [ValidateSet('WindowsServer2016', 'WindowsServer2019', 'WindowsServer2022', 'WindowsServer2025WSL', 'Windows10', 'SQLServer2017', 'SQLServer2019', 'SQLServer2022', 'Ubuntu22', 'AlmaLinux8')]
        [string]$SourceImage,
        [string]$VMSize = "Standard_B2s",
        [PSCredential]$Credential,
        [switch]$TrustedLaunch,
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
        } elseif ($SourceImage -like 'Ubuntu*' -or $SourceImage -like 'AlmaLinux*') {
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
        } elseif ($SourceImage -eq 'WindowsServer2025WSL') {
            $sourceImageParam = @{
                PublisherName = "MicrosoftWindowsServer"         # Get-AzVMImagePublisher -Location $location | Where-Object PublisherName -like microsoft*
                Offer         = "WindowsServer"                  # Get-AzVMImageOffer -Location $location -Publisher $sourceImageParam.PublisherName
                Skus          = "2025-datacenter-azure-edition"  # Get-AzVMImageSku -Location $location -Publisher $sourceImageParam.PublisherName -Offer $sourceImageParam.Offer | Select Skus
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

            if ($TrustedLaunch) {
                Write-PSFMessage -Level Verbose -Message 'Adding SecurityProfile'
                $vmConfig = Set-AzVmSecurityProfile -VM $vmConfig -SecurityType TrustedLaunch
                $vmConfig = Set-AzVmUefi -VM $vmConfig -EnableVtpm $true -EnableSecureBoot $true 
            }

            Write-PSFMessage -Level Verbose -Message 'Creating VM'
            $result = New-AzVM -ResourceGroupName $resourceGroupName -Location $location -VM $vmConfig -WarningAction SilentlyContinue 6> $null  # Suppress warning about future changes / Suppress info about Azure Trusted Launch VMs
            Write-PSFMessage -Level Verbose -Message "Result: IsSuccessStatusCode = $($result.IsSuccessStatusCode), StatusCode = $($result.StatusCode), ReasonPhrase = $($result.ReasonPhrase)"

            if ($SourceImage -match 'Ubuntu') {
                Write-PSFMessage -Level Verbose -Message 'Testing SSH connection'
                $waitUntil = [datetime]::Now.AddMinutes(5)
                while ([datetime]::Now -lt $waitUntil) {
                    try {
                        $session = New-MyAzureLabSSHSession -ComputerName $ComputerName -Credential $Credential 
                        $null = $session | Remove-SSHSession
                        break
                    } catch {
                        Write-PSFMessage -Level Verbose -Message "Failed: $_"
                        Start-Sleep -Seconds 10
                    }
                }
                Write-PSFMessage -Level Verbose -Message 'Updating packages'
                Invoke-MyAzureLabSSHCommand -ComputerName $ComputerName -Credential $Credential -Command 'sudo apt-get update'
                Write-PSFMessage -Level Verbose -Message 'Installing Powershell'
                $installPwshCommand = @(
                    'sudo apt-get -y install wget apt-transport-https software-properties-common'
                    'source /etc/os-release && wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb'
                    'sudo dpkg -i packages-microsoft-prod.deb'
                    'rm packages-microsoft-prod.deb'
                    'sudo apt-get update'
                    'sudo apt-get -y install powershell'
                )
                Invoke-MyAzureLabSSHCommand -ComputerName $ComputerName -Credential $Credential -Command $installPwshCommand
            } elseif ($SourceImage -match 'AlmaLinux') {
                Write-PSFMessage -Level Verbose -Message 'Testing SSH connection'
                $waitUntil = [datetime]::Now.AddMinutes(5)
                while ([datetime]::Now -lt $waitUntil) {
                    try {
                        $session = New-MyAzureLabSSHSession -ComputerName $ComputerName -Credential $Credential 
                        $null = $session | Remove-SSHSession
                        break
                    } catch {
                        Write-PSFMessage -Level Verbose -Message "Failed: $_"
                        Start-Sleep -Seconds 10
                    }
                }
                Write-PSFMessage -Level Verbose -Message 'Updating packages'
                Invoke-MyAzureLabSSHCommand -ComputerName $ComputerName -Credential $Credential -Command 'sudo dnf -y update'
                Write-PSFMessage -Level Verbose -Message 'Installing Powershell'
                Invoke-MyAzureLabSSHCommand -ComputerName $ComputerName -Credential $Credential -Command 'sudo dnf -y install https://github.com/PowerShell/PowerShell/releases/download/v7.4.1/powershell-7.4.1-1.rh.x86_64.rpm'
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
