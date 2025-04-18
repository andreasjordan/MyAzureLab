function Remove-MyAzureLabVM {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message "Removing virtual maschine $ComputerName"
            $null = Remove-AzVM -Name "$($ComputerName)_VM" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzDisk -DiskName "$($ComputerName)_Disk1.vhd" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzNetworkInterface -Name "$($ComputerName)_Interface" -ResourceGroupName $resourceGroupName -Force
            $null = Remove-AzPublicIpAddress -Name "$($ComputerName)_PublicIP" -ResourceGroupName $resourceGroupName -Force
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
