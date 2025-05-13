function Show-MyAzureLabResourceGroupInfo {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
            $resources = Get-AzResource -ResourceGroupName $resourceGroupName
            if ($resources) {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName containes these resources:"
                $resources | Format-Table -Property Name, ResourceType
                $vms = Get-AzVM -ResourceGroupName $resourceGroupName
                if ($vms) {
                    Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName contains these virtual maschines:"
                    Get-AzVM -ResourceGroupName $resourceGroupName -Status | Format-Table -Property Name, PowerState
                } else {
                    Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not contain any virtual maschines."
                }
                $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName
                if ($nsg) {
                    $sourceIP = $nsg.SecurityRules.SourceAddressPrefix | Select-Object -Unique
                    if ($homeIP -ne $sourceIP) {
                        Write-PSFMessage -Level Host -Message "Network security group uses source IP $sourceIp which is different from current home IP $homeIP. Network security group will be updated."
                        Set-MyAzureLabNSGRuleIPAddress -IpAddress $homeIP
                    }
                }
                $sqlServer = Get-AzSqlServer -ResourceGroupName $resourceGroupName
                foreach ($sql in $sqlServer) {
                    $sourceIP = (Get-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $sql.ServerName -Name AllowHome).StartIpAddress
                    if ($homeIP -ne $sourceIP) {
                        Write-PSFMessage -Level Host -Message "SQL Server firewall uses source IP $sourceIp which is different from current home IP $homeIP. SQL Server firewall will be updated."
                        Set-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $sql.ServerName -Name AllowHome -StartIpAddress $homeIP -EndIpAddress $homeIP
                    }
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not contain any resources."
            }
        } else {
            Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
        }
    }
}
