function Start-MyAzureLabResourceGroup {
    [CmdletBinding()]
    Param (
        [string[]]$OnlyComputerName,
        [string[]]$ExcludeComputerName,
        [switch]$EnableException
    )

    process {
        try {
            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Starting VMs in resource group $resourceGroupName."
                $vms = Get-AzVM -ResourceGroupName $resourceGroupName
                if ($OnlyComputerName) {
                    $onlyVMs = $OnlyComputerName | ForEach-Object { "$($_)_VM" }
                    $vms = $vms | Where-Object Name -in $onlyVMs
                }
                if ($ExcludeComputerName) {
                    $excludeVMs = $ExcludeComputerName | ForEach-Object { "$($_)_VM" }
                    $vms = $vms | Where-Object Name -notin $excludeVMs
                }
                $jobs = foreach ($vm in $vms) {
                    Write-PSFMessage -Level Verbose -Message "Starting $($vm.Name)"
                    Start-Job -ScriptBlock {
                        $using:vm | Start-AzVM
                    }
                }
                $null = Wait-Job -Job $jobs
                $result = Receive-Job -Job $jobs
                if ($result.Status -ne 'Succeeded') {
                    $result | Format-Table
                    Stop-PSFFunction -Message "Start failed for at least one VM" -Target $result
                } else {
                    Get-AzVM -ResourceGroupName $resourceGroupName -Status | Format-Table -Property Name, PowerState
                }
            } else {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName does not exist."
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
