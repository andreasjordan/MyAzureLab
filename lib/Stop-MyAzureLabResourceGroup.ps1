function Stop-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Stopping VMs in resource group $resourceGroupName."
                $vms = Invoke-MyAzureLabRetry -Activity 'Get-AzVM' -ScriptBlock {
                    Get-AzVM -ResourceGroupName $resourceGroupName
                }
                $jobs = foreach ($vm in $vms) {
                    Write-PSFMessage -Level Verbose -Message "Stopping $($vm.Name)"
                    Start-Job -ScriptBlock {
                        $using:vm | Stop-AzVM -Force
                    }
                }
                $null = Wait-Job -Job $jobs
                $result = Receive-Job -Job $jobs
                if ($result.Status -ne 'Succeeded') {
                    $result | Format-Table
                    Stop-PSFFunction -Message "Stop failed for at least one VM" -Target $result -EnableException $EnableException
                } else {
                    Invoke-MyAzureLabRetry -Activity 'Get-AzVM -Status' -ScriptBlock {
                        Get-AzVM -ResourceGroupName $resourceGroupName -Status
                    } | Format-Table -Property Name, PowerState
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
