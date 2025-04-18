function Get-MyAzureLabSFTPItem {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [string[]]$Path,
        [string]$Destination,
        [switch]$Force,
        [switch]$EnableException
    )

    try {
        if ($ComputerName) {
            $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
        }

        $sftpSessionParams = @{
            ComputerName  = $IPAddress
            Credential    = $Credential
            Force         = $true
            WarningAction = 'SilentlyContinue'
            ErrorAction   = 'Stop'
        }
        $sftpSession = New-SFTPSession @sftpSessionParams
    } catch {
        Stop-PSFFunction -Message "Error while creating sftp session to $($IPAddress): $_" -EnableException $EnableException
        return
    }

    try {
        Get-SFTPItem -SFTPSession $sftpSession -Path $Path -Destination $Destination -ErrorAction Stop
    } catch {
        Stop-PSFFunction -Message "Error while running sftp command: $_" -EnableException $EnableException
    } finally {
        $null = $sftpSession | Remove-SFTPSession
    }
}
