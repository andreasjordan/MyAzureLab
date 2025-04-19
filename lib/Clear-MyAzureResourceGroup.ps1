function Clear-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Removing virtual maschines, network security group, network and key vault from resource group $resourceGroupName"
                foreach ($vm in Get-AzVM -ResourceGroupName $resourceGroupName) {
                    $computerName = $vm.Name -replace '_VM$', ''
                    Write-PSFMessage -Level Host -Message "Removing $computerName"
                    Remove-MyAzureLabVM -ComputerName $computerName -EnableException
                }
                Remove-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup -Force
                Remove-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name VirtualNetwork -Force
                Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force
                $resources = Get-AzResource -ResourceGroupName $resourceGroupName
                if ($resources) {
                    Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName still containes these resources:"
                    $resources | Format-Table -Property Name, ResourceType
                }
            } else {
                Write-PSFMessage -Level Host -Message "ResourceGroup $resourceGroupName not found"
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
