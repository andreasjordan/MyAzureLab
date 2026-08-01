function Wait-MyAzureLabDeploymentCompletion {
    [CmdletBinding()]
    Param (
        [string]$StatusURL = $statusConfig.Uri,
        [string]$WaitFor = 'Finished deployment',
        [datetime]$OnlyStatusAfter = [datetime]::Now,
        [int]$Timeout = 7200,
        [switch]$EnableException
    )

    process {
        try {
            $waitUntil = [datetime]::Now.AddSeconds($Timeout)
            $finished = $false
            $failed = @( )
            while ([datetime]::Now -lt $waitUntil) {
                $data = (Invoke-WebRequest -Uri $StatusURL).Content | ConvertFrom-Json
                $data = $data | Where-Object { [datetime]$_.Time -gt $OnlyStatusAfter -and $_.Host -ne 'localhost' }
                Clear-Host
                Write-Host "Results from $StatusURL"
                $data | Sort-Object Time | Format-Table -Property IP, Host, Time, Message -Wrap
                # The deployment scripts report every error they give up on with a message starting with "Failed"
                $failed = @($data | Where-Object Message -match '^Failed')
                if ($failed.Count -gt 0) {
                    break
                }
                if ($WaitFor -eq ($data.Message | Select-Object -Unique)) {
                    $finished = $true
                    break
                }
                Start-Sleep -Seconds 10
            }
            if ($failed.Count -gt 0) {
                $failedMessage = ($failed | ForEach-Object -Process { "$($_.Host): $($_.Message)" }) -join ' | '
                Stop-PSFFunction -Message "Deployment failed on at least one virtual maschine: $failedMessage" -Target $failed -EnableException $EnableException
            } elseif (-not $finished) {
                Stop-PSFFunction -Message "Timeout after $Timeout seconds while waiting for '$WaitFor'" -Target $data -EnableException $EnableException
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
