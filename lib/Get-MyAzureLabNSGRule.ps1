function Get-MyAzureLabNSGRule {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            $nsg.SecurityRules | Format-Table -Property Name, DestinationPortRange, SourceAddressPrefix, Priority
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
