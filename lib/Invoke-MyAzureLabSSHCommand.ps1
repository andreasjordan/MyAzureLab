function Invoke-MyAzureLabSSHCommand {
    [CmdletBinding()]
    Param(
        [string]$ComputerName,
        [string]$IPAddress,
        [PSCredential]$Credential,
        [string[]]$Command,
        [int]$TimeOut = 9999,
        [int]$SuccessExitStatus = 0,
        [switch]$ShowOutput,
        [switch]$EnableException
    )
    
    try {
        $sshSession = New-MyAzureLabSSHSession -ComputerName $ComputerName -IPAddress $IPAddress -Credential $Credential -EnableException
    } catch {
        Stop-PSFFunction -Message "Error while creating ssh session to $($IPAddress): $_" -EnableException $EnableException
        return
    }

    $returnValue = $true
    foreach ($cmd in $Command) {
        if ($cmd -match '^nohup') {
            Write-PSFMessage -Level Verbose -Message "Using stream for: $cmd"
            $sshStream = New-SSHShellStream -SSHSession $sshSession
            Invoke-SSHStreamShellCommand -ShellStream $sshStream -Command $cmd
            Write-PSFMessage -Level Verbose -Message "Closing stream"
            $sshStream.Close()
        } else {
            $sshCommandParams = @{
                SSHSession               = $sshSession
                Command                  = $cmd
                EnsureConnection         = $true
                TimeOut                  = $TimeOut
                ShowStandardOutputStream = $ShowOutput
                ShowErrorOutputStream    = $ShowOutput
                ErrorAction              = 'Stop'
            }
            $sshResult = Invoke-SSHCommand @sshCommandParams
            if ($sshResult.ExitStatus -ne $SuccessExitStatus) {
                $returnValue = $false
                break
            }
        }
    }
    $null = $sshSession | Remove-SSHSession
    if ($returnValue -eq $false) {
        Stop-PSFFunction -Message "Command '$cmd' returned with ExitStatus $($sshResult.ExitStatus)" -EnableException $EnableException
    }
}
