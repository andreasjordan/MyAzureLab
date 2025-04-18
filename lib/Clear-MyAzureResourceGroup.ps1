function global:Clear-MyAzureLabResourceGroup {
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
                    Remove-MyAzureLabVM -ComputerName $computerName
                }
                Remove-AzNetworkSecurityGroup -ResourceGroupName $resourceGroupName -Name NetworkSecurityGroup -Force
                Remove-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name VirtualNetwork -Force
                Get-AzKeyVault -ResourceGroupName $resourceGroupName | Remove-AzKeyVault -Force
                # Only used in private subscription:
                # $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
                # Only used in private subscription:
                # Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
                Get-AzResource -ResourceGroupName $resourceGroupName
            } else {
                Write-PSFMessage -Level Host -Message "ResourceGroup $resourceGroupName not found"
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
