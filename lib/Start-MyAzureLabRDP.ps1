function Start-MyAzureLabRDP {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [switch]$EnableException
    )

    process {
        try {
            $ip = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
            $user = $Credential.UserName
            $pass = $Credential.GetNetworkCredential().Password
            $null = cmdkey /add:TERMSRV/$ip /user:$user /pass:$pass
            mstsc /v:$ip
            $target = [datetime]::Now.AddSeconds(15)
            while ([datetime]::Now -lt $target) {
                Start-Sleep -Milliseconds 100
                if ((Get-Process -Name mstsc -ErrorAction SilentlyContinue).MainWindowTitle -match "^$ip - ") {
                    break
                }
            }
            $null = cmdkey /delete:TERMSRV/$ip
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
