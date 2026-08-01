function Invoke-MyAzureLabCommand {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$Timeout = 600,
        [scriptblock]$ScriptBlock,
        [Object[]]$ArgumentList,
        [switch]$EnableException
    )

    process {
        $session = $null
        try {
            Write-PSFMessage -Level Verbose -Message "Creating PSSession"
            $session = New-MyAzureLabSession -ComputerName $ComputerName -Credential $Credential -Timeout $Timeout -EnableException
            Write-PSFMessage -Level Verbose -Message "Configuring PSSession"
            Invoke-Command -Session $session -ScriptBlock { $ErrorActionPreference = 'Stop' }
            Write-PSFMessage -Level Verbose -Message "Executing ScriptBlock"
            Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        } finally {
            if ($session) {
                Write-PSFMessage -Level Verbose -Message "Removing PSSession"
                # The session can already be gone, for example if the scriptblock rebooted the computer
                $session | Remove-PSSession -ErrorAction SilentlyContinue
            }
        }
    }
}
