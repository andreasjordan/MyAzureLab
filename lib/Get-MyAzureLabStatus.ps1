function Get-MyAzureLabStatus {
    <#
        Reads the current state of the status api. The api keeps only the newest message per ip,
        so this is a snapshot of "where is every virtual maschine right now".
    #>
    [CmdletBinding()]
    Param (
        [string]$StatusURL = $statusConfig.Uri,
        [switch]$EnableException
    )

    process {
        try {
            (Invoke-WebRequest -Uri $StatusURL -UseBasicParsing).Content | ConvertFrom-Json
        } catch {
            Stop-PSFFunction -Message "Failed to read the status api at $($StatusURL): $_" -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
