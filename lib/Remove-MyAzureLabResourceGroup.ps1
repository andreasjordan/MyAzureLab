function Remove-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Removing resource group $resourceGroupName"
                # Removing can fail for a moment while a resource is still in use, so retry any error
                $null = Invoke-MyAzureLabRetry -Activity 'Remove-AzResourceGroup' -RetryAnyError -WaitSeconds 10 -ScriptBlock {
                    Remove-AzResourceGroup -Name $resourceGroupName -Force
                }
                Write-PSFMessage -Level Host -Message "Removing key vault"
                Invoke-MyAzureLabRetry -Activity 'Remove-AzKeyVault (purge)' -RetryAnyError -WaitSeconds 10 -ScriptBlock {
                    Get-AzKeyVault -InRemovedState -WarningAction SilentlyContinue | ForEach-Object -Process { Remove-AzKeyVault -VaultName $_.VaultName -Location $_.Location -InRemovedState -Force }
                }
                Write-PSFMessage -Level Host -Message "Finished"
            } else {
                Write-PSFMessage -Level Host -Message "ResourceGroup $resourceGroupName not found"
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
