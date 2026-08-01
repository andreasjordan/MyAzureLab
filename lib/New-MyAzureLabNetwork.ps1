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
                Name                     = "AllowHttpFromHome"
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                Priority                 = "1003"
                SourceAddressPrefix      = $HomeIP
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                DestinationPortRange     = 80
                Access                   = "Allow"
            }
        )

        try {
            try {
                Write-PSFMessage -Level Verbose -Message 'Testing VirtualNetwork'
                $null = Invoke-MyAzureLabRetry -Activity "Get-AzVirtualNetwork $($virtualNetworkParam.Name)" -ScriptBlock {
                    Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name $virtualNetworkParam.Name
                }
            } catch {
                # New-AzVirtualNetworkSubnetConfig only builds an object in memory, no retry needed
                Write-PSFMessage -Level Verbose -Message 'Creating VirtualNetworkSubnetConfig'
                $virtualNetworkSubnetConfig = New-AzVirtualNetworkSubnetConfig @virtualNetworkSubnetConfigParam
                Write-PSFMessage -Level Verbose -Message 'Creating VirtualNetwork'
                $null = Invoke-MyAzureLabRetry -Activity "New-AzVirtualNetwork $($virtualNetworkParam.Name)" -ScriptBlock {
                    New-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Location $location @virtualNetworkParam -Subnet $virtualNetworkSubnetConfig
                }
            }

            try {
                Write-PSFMessage -Level Verbose -Message 'Testing NetworkSecurityGroup'
                $null = Invoke-MyAzureLabRetry -Activity "Get-AzNetworkSecurityGroup $($networkSecurityGroupParam.Name)" -ScriptBlock {
                    Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name $networkSecurityGroupParam.Name
                }
            } catch {
                # New-AzNetworkSecurityRuleConfig only builds objects in memory, no retry needed
                Write-PSFMessage -Level Verbose -Message 'Creating NetworkSecurityRuleConfig for SecurityRules'
                $securityRules = foreach ($networkSecurityRuleConfigParam in $networkSecurityRules) {
                    New-AzNetworkSecurityRuleConfig @networkSecurityRuleConfigParam
                }
                Write-PSFMessage -Level Verbose -Message 'Creating NetworkSecurityGroup'
                $null = Invoke-MyAzureLabRetry -Activity "New-AzNetworkSecurityGroup $($networkSecurityGroupParam.Name)" -ScriptBlock {
                    New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Location $location @networkSecurityGroupParam -SecurityRules $securityRules
                }
            }

            Write-PSFMessage -Level Verbose -Message 'Network is ready'
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
