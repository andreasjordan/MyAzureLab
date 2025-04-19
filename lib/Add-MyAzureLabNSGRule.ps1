function Add-MyAzureLabNSGRule {
    [CmdletBinding()]
    Param (
        [int]$Port,
        [string[]]$IPAddress,
        [switch]$EnableException
    )

    process {
        try {
            $priority = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup |
                Select-Object -ExpandProperty SecurityRules |
                Sort-Object Priority |
                Select-Object -Last 1 -ExpandProperty Priority
            $priority++
            $ruleConfigParams = @{
                Name                     = "Allow$Port"
                DestinationPortRange     = $Port
                SourceAddressPrefix      = $IPAddress
                Priority                 = $priority
                Protocol                 = "Tcp"
                Direction                = "Inbound"
                SourcePortRange          = "*"
                DestinationAddressPrefix = "*"
                Access                   = "Allow"
            }
            $null = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup |
                Add-AzNetworkSecurityRuleConfig @ruleConfigParams |
                Set-AzNetworkSecurityGroup
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
