function Wait-MyAzureLabDeploymentCompletion {
    [CmdletBinding()]
    Param (
        [string]$WaitFor = 'Finished deployment',
        [datetime]$OnlyStatusAfter = [datetime]::Now,
        [switch]$EnableException
    )

    process {
        try {
            $statusApiPublicIP = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "STATUS_PublicIP").IpAddress
            while (1) {
                $data = (Invoke-WebRequest -Uri "http://$($statusApiPublicIP):8000/status").Content | ConvertFrom-Json
                $data = $data | Where-Object { [datetime]$_.Time -gt $OnlyStatusAfter }  
                Clear-Host
                Write-Host "Results from http://$($statusApiPublicIP):8000"
                $data | Sort-Object Time | Format-Table -Property IP, Host, Time, Message -Wrap
                if ($WaitFor -eq ($data.Message | Select-Object -Unique)) {
                    break
                }
                Start-Sleep -Seconds 10
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
