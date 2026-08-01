function New-MyAzureLabSession {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$Timeout = 600,
        [switch]$EnableException
    )

    $ipAddress = Invoke-MyAzureLabRetry -Activity "Get-AzPublicIpAddress $($ComputerName)_PublicIP" -ScriptBlock {
        (Get-AzPublicIpAddress -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_PublicIP").IpAddress
    }
    Write-PSFMessage -Level Verbose -Message "Using IP address $ipAddress"

    $vm = Invoke-MyAzureLabRetry -Activity "Get-AzVM $($ComputerName)_VM" -ScriptBlock {
        Get-AzVM -ResourceGroupName $resourceGroupName -Name "$($ComputerName)_VM"
    }
    if ($vm.OSProfile.WindowsConfiguration) {
        $vmIsWindows = $true
        $psSessionParam = @{
            ConnectionUri  = "https://$($ipAddress):5986"
            Credential     = $Credential
            SessionOption  = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            Authentication = "Negotiate"
            ErrorAction    = 'Stop'
        }
    } elseif ($vm.OSProfile.LinuxConfiguration) {
        $vmIsLinux = $true
        $sshSessionParam = @{
            ComputerName = $ipAddress
            Credential   = $Credential
            AcceptKey    = $true
            ErrorAction  = 'Stop'
        }
    } else {
        Stop-PSFFunction -Message "Unknown operating system for computer name $ComputerName" -EnableException $EnableException
        return
    }

    $waitUntil = (Get-Date).AddSeconds($Timeout)
    $sessionCreated = $false

    Write-PSFMessage -Level Verbose -Message 'Creating Session'
    while ((Get-Date) -lt $waitUntil) {
        try {
            if ($vmIsWindows) {
                New-PSSession @psSessionParam
            } elseif ($vmIsLinux) {
                New-SSHSession @sshSessionParam
            }
            $sessionCreated = $true
            break
        } catch {
            $lastError = $_
            Write-PSFMessage -Level Verbose -Message "Failed with: $lastError"
            Start-Sleep -Seconds 15
        }
    }
    # Do not test the time here: creating the session can succeed on an attempt that started
    # just before $waitUntil, and we would then report a failure for a session we just created
    if (-not $sessionCreated) {
        Stop-PSFFunction -Message "Operation timed out. Last error message: $lastError" -EnableException $EnableException
    }
}
