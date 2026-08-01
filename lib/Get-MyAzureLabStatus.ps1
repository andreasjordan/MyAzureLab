function Get-MyAzureLabStatus {
    <#
        Reads the current state of the status api. The api keeps only the newest message per ip,
        so this is a snapshot of "where is every virtual maschine right now".
    #>
    [CmdletBinding()]
    Param (
        [string]$StatusURL,
        [switch]$EnableException
    )

    process {
        # $statusConfig.Uri is only filled while create_VMs.ps1 runs, so fall back to the
        # permanent api. Without that the command cannot be used in a plain init session.
        if (-not $StatusURL) {
            $StatusURL = $statusConfig.Uri
        }
        if (-not $StatusURL) {
            $StatusURL = $Env:MyStatusURL
        }
        if (-not $StatusURL) {
            Stop-PSFFunction -Message 'No url for the status api. Set $Env:MyStatusURL, or pass -StatusURL, or run this while create_VMs.ps1 has set $statusConfig.Uri.' -EnableException $EnableException
            return
        }

        try {
            (Invoke-WebRequest -Uri $StatusURL -UseBasicParsing).Content | ConvertFrom-Json
        } catch {
            Stop-PSFFunction -Message "Failed to read the status api at $($StatusURL): $_" -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
