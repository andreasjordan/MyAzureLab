function global:Remove-MyAzureLabNSGRule {
    [CmdletBinding()]
    Param (
        [string]$Name,
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            $null = Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name $Name
            $null = $nsg | Set-AzNetworkSecurityGroup
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
