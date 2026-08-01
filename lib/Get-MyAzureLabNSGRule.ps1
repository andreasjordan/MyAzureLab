function Get-MyAzureLabNSGRule {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Invoke-MyAzureLabRetry -Activity 'Get-AzNetworkSecurityGroup' -ScriptBlock {
                Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            }
            $nsg.SecurityRules | Format-Table -Property Name, DestinationPortRange, SourceAddressPrefix, Priority
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
