function Show-MyAzureLabResourceGroupInfo {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                $resources = Invoke-MyAzureLabRetry -Activity 'Get-AzResource' -ScriptBlock {
                    Get-AzResource -ResourceGroupName $resourceGroupName
                }
                if ($resources) {
                    Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName contains these resources:"
                    $resources | Format-Table -Property Name, ResourceType
                    $vms = Invoke-MyAzureLabRetry -Activity 'Get-AzVM' -ScriptBlock {
                        Get-AzVM -ResourceGroupName $resourceGroupName
                    }
                    if ($vms) {
                        Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName contains these virtual machines:"
                        Invoke-MyAzureLabRetry -Activity 'Get-AzVM -Status' -ScriptBlock {
                            Get-AzVM -ResourceGroupName $resourceGroupName -Status
                        } | Format-Table -Property Name, PowerState
                    } else {
                        Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not contain any virtual machines."
                    }
                    $nsg = Invoke-MyAzureLabRetry -Activity 'Get-AzNetworkSecurityGroup' -ScriptBlock {
                        Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName
                    }
                    if ($nsg) {
                        # Only the rules created by New-MyAzureLabNetwork follow the home IP.
                        # Rules added later with Add-MyAzureLabNSGRule keep their own source address.
                        $outdatedRules = $nsg.SecurityRules | Where-Object { $_.Name -like '*FromHome' -and $_.SourceAddressPrefix -notcontains $homeIP }
                        if ($outdatedRules) {
                            $outdatedIP = $outdatedRules.SourceAddressPrefix | Select-Object -Unique
                            Write-PSFMessage -Level Host -Message "Network security group uses source IP $($outdatedIP -join ', ') which is different from current home IP $homeIP. Network security group will be updated."
                            Set-MyAzureLabNSGRuleIPAddress -IPAddress $homeIP -Name $outdatedRules.Name -EnableException:$EnableException
                        }
                    }
                    # Get-AzSqlServer needs the module Az.Sql, which is not imported by MyAzureLab.ps1,
                    # so only ask for sql servers if the resource group really contains one
                    if ($resources.ResourceType -contains 'Microsoft.Sql/servers') {
                        if (Get-Command -Name Get-AzSqlServer -ErrorAction SilentlyContinue) {
                            $sqlServers = Invoke-MyAzureLabRetry -Activity 'Get-AzSqlServer' -ScriptBlock {
                                Get-AzSqlServer -ResourceGroupName $resourceGroupName
                            }
                            foreach ($sql in $sqlServers) {
                                $firewallRule = Get-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $sql.ServerName -Name AllowHome -ErrorAction SilentlyContinue
                                if ($firewallRule -and $firewallRule.StartIpAddress -ne $homeIP) {
                                    Write-PSFMessage -Level Host -Message "SQL Server firewall uses source IP $($firewallRule.StartIpAddress) which is different from current home IP $homeIP. SQL Server firewall will be updated."
                                    $null = Invoke-MyAzureLabRetry -Activity 'Set-AzSqlServerFirewallRule' -ScriptBlock {
                                        Set-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $sql.ServerName -Name AllowHome -StartIpAddress $homeIP -EndIpAddress $homeIP
                                    }
                                }
                            }
                        } else {
                            Write-PSFMessage -Level Warning -Message "Resource group $resourceGroupName contains a SQL Server, but the module Az.Sql is not available, so the firewall rule is not checked."
                        }
                    }
                } else {
                    Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not contain any resources."
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
