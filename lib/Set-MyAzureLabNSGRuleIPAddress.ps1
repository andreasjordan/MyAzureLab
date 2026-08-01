function Set-MyAzureLabNSGRuleIPAddress {
    [CmdletBinding()]
    Param (
        [string[]]$IPAddress,
        [string[]]$Name,
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Invoke-MyAzureLabRetry -Activity 'Get-AzNetworkSecurityGroup' -ScriptBlock {
                Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            }
            $rules = $nsg.SecurityRules
            if ($Name) {
                $rules = $rules | Where-Object Name -in $Name
            }
            foreach ($rule in $rules) {
                $rule.SourceAddressPrefix = $IPAddress
            }
            $null = Invoke-MyAzureLabRetry -Activity 'Set-AzNetworkSecurityGroup' -ScriptBlock {
                $nsg | Set-AzNetworkSecurityGroup
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
