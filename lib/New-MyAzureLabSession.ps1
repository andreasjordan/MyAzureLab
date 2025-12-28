function New-MyAzureLabSession {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$Timeout = 600,
        [switch]$EnableException
    )

    $ipAddress = (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
    Write-PSFMessage -Level Verbose -Message "Using IP address $ipAddress"

    $vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_VM"
    if ($vm.OSProfile.WindowsConfiguration) {
        $vmIsWindows = $true
        $psSessionParam = @{
            ConnectionUri  = "https://$($ipAddress):5986"
            Credential     = $Credential
            SessionOption  = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            Authentication = "Negotiate"
        }
    } elseif ($vm.OSProfile.LinuxConfiguration) {
        $vmIsLinux = $true
        $sshSessionParam = @{
            ComputerName = $ipAddress
            Credential   = $Credential
            AcceptKey    = $true
        }
    } else {
        Stop-PSFFunction -Message "Unknown operating system for computer name $ComputerName" -EnableException $EnableException
        return
    }

    $waitUntil = (Get-Date).AddSeconds($Timeout)

    Write-PSFMessage -Level Verbose -Message 'Creating Session'
    while ((Get-Date) -lt $waitUntil) {
        try {
            if ($vmIsWindows) {
                New-PSSession @psSessionParam
            } elseif ($vmIsLinux) {
                New-SSHSession @sshSessionParam
            }
            break
        } catch {
            $lastError = $_
            Write-PSFMessage -Level Verbose -Message "Failed with: $lastError"
            Start-Sleep -Seconds 15
        }
    }
    if ((Get-Date) -ge $waitUntil) {
        Stop-PSFFunction -Message "Operation timed out. Last error message: $lastError" -EnableException $EnableException
    }
}
