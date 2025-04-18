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
