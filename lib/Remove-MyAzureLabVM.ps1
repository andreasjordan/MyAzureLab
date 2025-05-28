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
                $ComputerName = Get-AzVM -ResourceGroupName $resourceGroupName | ForEach-Object -Process { $_.Name -replace '_VM$', '' }
            } catch {
                Stop-PSFFunction -Message "Get-AzVM failed: $_" -ErrorRecord $_ -EnableException $EnableException
                return
            }
        }
        foreach ($name in $ComputerName) {
            Write-PSFMessage -Level Verbose -Message "Removing virtual maschine $name"
            
            $retry = 0
            while ($true) {
                try {
                    Write-PSFMessage -Level Verbose -Message "Removing $($name)_VM"
                    $null = Get-AzVM -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_VM" | Remove-AzVM -Force
                    break
                } catch {
                    Write-PSFMessage -Level Warning -Message "Remove-AzVM failed: $_" -ErrorRecord $_
                    Start-Sleep -Seconds 10
                    $retry++
                    if ($retry -eq 3) {
                        Stop-PSFFunction -Message "Remove-AzVM failed: $_" -ErrorRecord $_ -EnableException $EnableException
                        return
                    }
                }
            }

            $retry = 0
            while ($true) {
                try {
                    Write-PSFMessage -Level Verbose -Message "Removing $($name)_Disk1.vhd"
                    $null = Get-AzDisk -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_Disk1.vhd" | Remove-AzDisk -Force
                    break
                } catch {
                    Write-PSFMessage -Level Warning -Message "Remove-AzDisk failed: $_" -ErrorRecord $_
                    Start-Sleep -Seconds 10
                    $retry++
                    if ($retry -eq 3) {
                        Stop-PSFFunction -Message "Remove-AzDisk failed: $_" -ErrorRecord $_ -EnableException $EnableException
                        return
                    }
                }
            }

            $retry = 0
            while ($true) {
                try {
                    Write-PSFMessage -Level Verbose -Message "Removing $($name)_Interface"
                    $null = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_Interface" | Remove-AzNetworkInterface -Force
                    break
                } catch {
                    Write-PSFMessage -Level Warning -Message "Remove-AzNetworkInterface failed: $_" -ErrorRecord $_
                    Start-Sleep -Seconds 10
                    $retry++
                    if ($retry -eq 3) {
                        Stop-PSFFunction -Message "Remove-AzNetworkInterface failed: $_" -ErrorRecord $_ -EnableException $EnableException
                        return
                    }
                }
            }

            $retry = 0
            while ($true) {
                try {
                    Write-PSFMessage -Level Verbose -Message "Removing $($name)_PublicIP"
                    $null = Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName | Where-Object Name -eq "$($name)_PublicIP" | Remove-AzPublicIpAddress -Force
                    break
                } catch {
                    Write-PSFMessage -Level Warning -Message "Remove-AzPublicIpAddress failed: $_" -ErrorRecord $_
                    Start-Sleep -Seconds 10
                    $retry++
                    if ($retry -eq 3) {
                        Stop-PSFFunction -Message "Remove-AzPublicIpAddress failed: $_" -ErrorRecord $_ -EnableException $EnableException
                        return
                    }
                }
            }
        }
    }
}
