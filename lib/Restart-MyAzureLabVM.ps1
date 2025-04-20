function Restart-MyAzureLabVM {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [switch]$EnableException
    )

    process {
        try {
            $result = Restart-AzVM -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_VM"
            if ($result.Status -ne 'Succeeded') {
                $result | Format-Table
                Stop-PSFFunction -Message "Restart failed: $($result.Error)" -EnableException $EnableException
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
