function Remove-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string[]]$ComputerName,
        [switch]$All,
        [switch]$EnableException
    )

    process {
        if ($All) {
            try {
                $ComputerName = Invoke-MyAzureLabRetry -Activity 'Get-AzVM' -ScriptBlock {
                    Get-AzVM -ResourceGroupName $resourceGroupName
                } | ForEach-Object -Process { $_.Name -replace '_VM$', '' }
            } catch {
                Stop-PSFFunction -Message "Get-AzVM failed: $_" -ErrorRecord $_ -EnableException $EnableException
                return
            }
        }
        foreach ($name in $ComputerName) {
            Write-PSFMessage -Level Verbose -Message "Removing virtual maschine $name"

            # Removing can fail for a moment while a resource is still in use, so any error is
            # worth another attempt here, not only the transient network ones
            $resources = @(
                @{ Activity = "Remove-AzVM $($name)_VM"              ; ScriptBlock = { Get-AzVM -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_VM" | Remove-AzVM -Force } }
                @{ Activity = "Remove-AzDisk $($name)_Disk1.vhd"     ; ScriptBlock = { Get-AzDisk -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_Disk1.vhd" | Remove-AzDisk -Force } }
                @{ Activity = "Remove-AzNetworkInterface $($name)_Interface" ; ScriptBlock = { Get-AzNetworkInterface -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_Interface" | Remove-AzNetworkInterface -Force } }
                @{ Activity = "Remove-AzPublicIpAddress $($name)_PublicIP"   ; ScriptBlock = { Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_PublicIP" | Remove-AzPublicIpAddress -Force } }
            )

            foreach ($resource in $resources) {
                try {
                    Write-PSFMessage -Level Verbose -Message $resource.Activity
                    $null = Invoke-MyAzureLabRetry -Activity $resource.Activity -ScriptBlock $resource.ScriptBlock -RetryAnyError -WaitSeconds 10
                } catch {
                    Stop-PSFFunction -Message "$($resource.Activity) failed: $_" -ErrorRecord $_ -EnableException $EnableException
                    return
                }
            }
        }
    }
}
