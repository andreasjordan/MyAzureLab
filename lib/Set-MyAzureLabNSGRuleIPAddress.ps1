function Set-MyAzureLabNSGRuleIPAddress {
    [CmdletBinding()]
    Param (
        [string[]]$IPAddress,
        [string[]]$Name,
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            $rules = $nsg.SecurityRules
            if ($Name) {
                $rules = $rules | Where-Object Name -in $Name
            }
            foreach ($rule in $rules) {
                $rule.SourceAddressPrefix = $IPAddress
            }
            $null = $nsg | Set-AzNetworkSecurityGroup
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
