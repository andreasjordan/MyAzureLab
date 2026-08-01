function Remove-MyAzureLabNSGRule {
    [CmdletBinding()]
    Param (
        [string]$Name,
        [switch]$EnableException
    )

    process {
        try {
            $nsg = Invoke-MyAzureLabRetry -Activity 'Get-AzNetworkSecurityGroup' -ScriptBlock {
                Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup
            }
            # Remove-AzNetworkSecurityRuleConfig only changes the object in memory, no retry needed
            $null = Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name $Name
            $null = Invoke-MyAzureLabRetry -Activity 'Set-AzNetworkSecurityGroup' -ScriptBlock {
                $nsg | Set-AzNetworkSecurityGroup
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
