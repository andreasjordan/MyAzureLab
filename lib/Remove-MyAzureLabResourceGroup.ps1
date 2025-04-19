function Remove-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Removing resource group $resourceGroupName"
                $null = Remove-AzResourceGroup -Name $resourceGroupName -Force
                Write-PSFMessage -Level Host -Message "Removing key vault"
                Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
                Write-PSFMessage -Level Host -Message "Finished"
            } else {
                Write-PSFMessage -Level Host -Message "ResourceGroup $resourceGroupName not found"
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
