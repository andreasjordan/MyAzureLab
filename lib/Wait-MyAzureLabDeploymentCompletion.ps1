function Wait-MyAzureLabDeploymentCompletion {
    <#
        Waits until every given virtual maschine has reported $WaitFor.

        Times are deliberately not compared. The status api and this computer can run in
        different time zones and the messages carry no utc offset, so comparing them against
        the local clock silently filters out either too much or too little. Instead a virtual
        maschine counts as "has reported for this part" as soon as its Time *string* differs
        from the one in the snapshot that was taken before the part was started.

        Only the given computers are looked at. The status api can be shared with other
        projects, whose messages would otherwise never match $WaitFor and stall the wait.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string[]]$ComputerName,
        [PSCustomObject[]]$StatusBefore,
        [string]$StatusURL = $statusConfig.Uri,
        [string]$WaitFor = 'Finished deployment',
        [int]$Timeout = 7200,
        [switch]$EnableException
    )

    process {
        try {
            $timeBefore = @{ }
            foreach ($entry in $StatusBefore) {
                $timeBefore[$entry.Host] = $entry.Time
            }

            $waitUntil = [datetime]::Now.AddSeconds($Timeout)
            $finished = $false
            $failed = @( )
            $data = @( )
            while ([datetime]::Now -lt $waitUntil) {
                $data = @(Get-MyAzureLabStatus -StatusURL $StatusURL -EnableException)
                $mine = @($data | Where-Object { $_.Host -in $ComputerName })
                # A computer that never reported before has no entry in $timeBefore, so its
                # first message already counts as new
                $reported = @($mine | Where-Object { $_.Time -ne $timeBefore[$_.Host] })
                $waitingFor = @($ComputerName | Where-Object { $_ -notin $reported.Host })

                Clear-Host
                Write-Host "Results from $StatusURL"
                $mine | Sort-Object -Property Host | Format-Table -Property IP, Host, Time, Message -Wrap
                if ($waitingFor.Count -gt 0) {
                    Write-Host "Still waiting for: $($waitingFor -join ', ')"
                }

                # The deployment scripts report every error they give up on with a message
                # starting with "Failed"
                $failed = @($reported | Where-Object Message -match '^Failed')
                if ($failed.Count -gt 0) {
                    break
                }
                if ($waitingFor.Count -eq 0 -and ($reported.Message | Select-Object -Unique) -eq $WaitFor) {
                    $finished = $true
                    break
                }
                Start-Sleep -Seconds 10
            }

            if ($failed.Count -gt 0) {
                $failedMessage = ($failed | ForEach-Object -Process { "$($_.Host): $($_.Message)" }) -join ' | '
                Stop-PSFFunction -Message "Deployment failed on at least one virtual maschine: $failedMessage" -Target $failed -EnableException $EnableException
            } elseif (-not $finished) {
                Stop-PSFFunction -Message "Timeout after $Timeout seconds while waiting for '$WaitFor' on: $($ComputerName -join ', ')" -Target $data -EnableException $EnableException
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
