function Send-MyAzureLabStatus {
    [CmdletBinding()]
    Param(
        [string]$Message
    )

    process {
        if ($Env:MyStatusURL) {
            $requestParams = @{
                Uri             = $Env:MyStatusURL
                Method          = 'Post'
                ContentType     = 'application/json'
                Body            = @{
                    IP      = '127.0.0.1'
                    Host    = 'localhost'
                    Message = $Message
                } | ConvertTo-Json -Compress
                UseBasicParsing = $true
            }
            try {
                $null = Invoke-WebRequest @requestParams
            } catch {
                # Ignore errors
            }
        }
    }
}