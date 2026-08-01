function Invoke-MyAzureLabRetry {
    <#
        Runs an Azure command and retries it if it fails with a transient network error.

        Only errors that look transient are retried. Every other error is rethrown at once and
        unchanged, so the surrounding try/catch keeps working exactly as before - for example the
        "does this resource already exist" tests in New-MyAzureLabVM, which rely on Get-Az... to
        throw when the resource is not there.

        Use -RetryAnyError where any error is worth another attempt, for example when removing
        resources that can still be in use for a moment.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [string]$Activity = 'Azure call',
        # On 2026-08-01 two New-AzVM calls only succeeded on the third attempt, so 3 was just
        # barely enough. 5 gives some room without waiting too long on a real outage.
        [int]$Retries = 5,
        [int]$WaitSeconds = 15,
        [switch]$RetryAnyError
    )

    # Seen in practice on 2026-08-01: "An error occurred while sending the request." out of
    # New-AzVM, Remove-AzVM and Remove-AzDisk, five times within two hours. In every case the
    # operation had actually succeeded in Azure, only the response never made it back.
    $transientMessage = @(
        'An error occurred while sending the request'
        'The SSL connection could not be established'
        'The operation was canceled'
        'A task was canceled'
        'Unable to read data from the transport connection'
        'The remote name could not be resolved'
        'The underlying connection was closed'
    ) -join '|'

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            $isTransient = $false
            for ($exception = $_.Exception; $exception; $exception = $exception.InnerException) {
                if ($exception.Message -match $transientMessage) {
                    $isTransient = $true
                    break
                }
            }
            if (-not ($isTransient -or $RetryAnyError) -or $attempt -ge $Retries) {
                throw
            }
            Write-PSFMessage -Level Warning -Message "$Activity failed, retrying in $WaitSeconds seconds (attempt $attempt of $Retries): $_"
            Start-Sleep -Seconds $WaitSeconds
        }
    }
}
