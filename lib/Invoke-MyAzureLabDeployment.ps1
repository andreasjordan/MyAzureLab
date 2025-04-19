function Invoke-MyAzureLabDeployment {
    [CmdletBinding()]
    Param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$Path,
        [PSCustomObject]$Config,
        [scriptblock]$ScriptBlock,
        [switch]$EnableException
    )

    process {
        try {
            $session = New-MyAzureLabSession -ComputerName $ComputerName -Credential $Credential -EnableException
            $commandParams = @{
                Session = $session
            }

            if ($Path) {
                $script = Get-Content -Path $Path -Encoding UTF8 -Raw
                $commandParams.ArgumentList = $script, $Config
                $commandParams.ScriptBlock = {
                    Param(
                        [string]$Script,
                        [PSCustomObject]$Config
                    )
    
                    $ErrorActionPreference = 'Stop'
    
                    if (-not (Test-Path -Path C:\Deployment)) {
                        $null = New-Item -Path C:\Deployment -ItemType Directory
                    }
                    Set-Content -Path C:\Deployment\deployment.ps1 -Value $Script -Encoding UTF8
                    Set-Content -Path C:\Deployment\config.txt -Value ($Config | ConvertTo-Json -Depth 99) -Encoding UTF8
    
                    if ((Get-ScheduledTask).TaskName -notcontains 'DeploymentAtStartup') {
                        $scheduledTaskActionParams = @{
                            Execute  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                            Argument = '-ExecutionPolicy RemoteSigned -NonInteractive -File C:\Deployment\deployment.ps1'
                        }
                        $scheduledTaskParams = @{
                            TaskName = 'DeploymentAtStartup'
                            Trigger  = New-ScheduledTaskTrigger -AtStartup
                            User     = 'SYSTEM'
                            Action   = New-ScheduledTaskAction @scheduledTaskActionParams
                        }
                        $null = Register-ScheduledTask @scheduledTaskParams
                    }
    
                    Start-ScheduledTask -TaskName DeploymentAtStartup
                }
            } elseif ($ScriptBlock) {
                $commandParams.ScriptBlock = $ScriptBlock
            }

            Write-PSFMessage -Level Verbose -Message "Starting Invoke-Command"
            Invoke-Command @commandParams
            Write-PSFMessage -Level Verbose -Message "Finished Invoke-Command"
            $session | Remove-PSSession
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
