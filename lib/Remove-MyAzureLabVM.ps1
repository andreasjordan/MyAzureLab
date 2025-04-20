function Remove-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string[]]$ComputerName,
        [switch]$All,
        [switch]$EnableException
    )

    process {
        try {
            if ($All) {
                $ComputerName = Get-AzVM -ResourceGroupName $resourceGroupName | ForEach-Object -Process { $_.Name -replace '_VM$', '' }
            }
            foreach ($name in $ComputerName) {
                Write-PSFMessage -Level Verbose -Message "Removing virtual maschine $name"
                $null = Remove-AzVM -Name "$($name)_VM" -ResourceGroupName $resourceGroupName -Force
                $null = Remove-AzDisk -DiskName "$($name)_Disk1.vhd" -ResourceGroupName $resourceGroupName -Force
                $null = Remove-AzNetworkInterface -Name "$($name)_Interface" -ResourceGroupName $resourceGroupName -Force
                $null = Remove-AzPublicIpAddress -Name "$($name)_PublicIP" -ResourceGroupName $resourceGroupName -Force
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
