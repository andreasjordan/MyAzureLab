function Clear-MyAzureLabResourceGroup {
    <#
        Empties the resource group without removing the resource group itself: all virtual
        maschines, then the network security group, the virtual network and the key vault.

        This is meant for a resource group that was handed to me in someone else's
        subscription. I am not allowed to delete such a resource group, and I could not
        recreate it either, so this command clears out everything inside it and leaves an empty
        resource group behind to start over with.

        In my own subscription there is no need for it:
        * Remove-MyAzureLabVM -All removes only the virtual maschines, which is what I use to
          save money while keeping the network and the key vault.
        * Remove-MyAzureLabResourceGroup removes the resource group as a whole, which is fine
          there because I can simply create it again.
    #>
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Removing virtual maschines, network security group, network and key vault from resource group $resourceGroupName"
                $vms = Invoke-MyAzureLabRetry -Activity 'Get-AzVM' -ScriptBlock {
                    Get-AzVM -ResourceGroupName $resourceGroupName
                }
                foreach ($vm in $vms) {
                    $computerName = $vm.Name -replace '_VM$', ''
                    Write-PSFMessage -Level Host -Message "Removing $computerName"
                    Remove-MyAzureLabVM -ComputerName $computerName -EnableException
                }
                # Removing can fail for a moment while a resource is still in use, so retry any error
                Invoke-MyAzureLabRetry -Activity 'Remove-AzNetworkSecurityGroup' -RetryAnyError -WaitSeconds 10 -ScriptBlock {
                    Remove-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup -Force
                }
                Invoke-MyAzureLabRetry -Activity 'Remove-AzVirtualNetwork' -RetryAnyError -WaitSeconds 10 -ScriptBlock {
                    Remove-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name VirtualNetwork -Force
                }
                Invoke-MyAzureLabRetry -Activity 'Remove-AzKeyVault' -RetryAnyError -WaitSeconds 10 -ScriptBlock {
                    Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force
                }
                $resources = Invoke-MyAzureLabRetry -Activity 'Get-AzResource' -ScriptBlock {
                    Get-AzResource -ResourceGroupName $resourceGroupName
                }
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
