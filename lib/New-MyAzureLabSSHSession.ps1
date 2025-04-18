function New-MyAzureLabSSHSession {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [switch]$EnableException
    )
    
    try {
        if ($ComputerName) {
            $IPAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            Write-PSFMessage -Level Verbose -Message "Using IP address $IPAddress"
        }

        $sshSessionParams = @{
            ComputerName  = $IPAddress
            Credential    = $Credential
            Force         = $true
            WarningAction = 'SilentlyContinue'
            ErrorAction   = 'Stop'
        }
        New-SSHSession @sshSessionParams
    } catch {
        Stop-PSFFunction -Message "Error while creating ssh session to $($IPAddress): $_" -EnableException $EnableException
        return
    }
}
