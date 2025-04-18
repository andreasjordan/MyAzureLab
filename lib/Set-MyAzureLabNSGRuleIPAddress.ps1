function global:Set-MyAzureLabNSGRuleIPAddress {
    [CmdletBinding()]
    Param (
        [string[]]$IPAddress,
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            foreach ($rule in $nsg.SecurityRules) {
                $rule.SourceAddressPrefix = $IPAddress
            }
            $null = $nsg | Set-AzNetworkSecurityGroup
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
