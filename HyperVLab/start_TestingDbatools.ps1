$ErrorActionPreference = 'Continue'

Import-Module -Name AutomatedLab

$LabName          = 'TestingDbatools'
$LabNetworkBase   = '192.168.3'
$LabAdminUser     = 'Admin'
$LabAdminPassword = 'P@ssw0rd'
$LabDomainName    = 'ordix.local'

# This script runs at every RDP logon on BASE (Run key registered by create_BASE.ps1), so it
# must do nothing while the lab is not installed yet.
try {
    Import-Lab -Name $LabName -NoValidation -ErrorAction Stop
} catch {
    Write-Host "Lab $LabName is not installed, nothing to start"
    return
}
Start-LabVM -ComputerName DC -Wait ; Start-LabVM -All -Wait
# RDP answers on 3389 almost immediately, but the domain logon hangs at the login screen
# until Active Directory on DC answers logon requests and ADMIN01 has a secure channel to
# the domain. So wait for exactly that instead of sleeping blindly. The probes must not
# throw: an exception here would abort the script before the RDP connection is opened.
try {
    Wait-LabADReady -ComputerName DC -TimeoutInMinutes 10
    $logonReady = Invoke-LabCommand -ComputerName ADMIN01 -ActivityName 'Waiting for domain logon readiness' -PassThru -ScriptBlock {
        $deadline = [datetime]::Now.AddMinutes(5)
        while ([datetime]::Now -lt $deadline) {
            if ((Get-Service -Name TermService).Status -eq 'Running' -and (Test-ComputerSecureChannel)) {
                return $true
            }
            Start-Sleep -Seconds 10
        }
        $false
    }
    if (-not $logonReady) {
        Write-Host 'ADMIN01 did not report domain logon readiness in time, trying RDP anyway...'
    }
} catch {
    Write-Host "Readiness probes failed ($_), falling back to a fixed wait"
    Start-Sleep -Seconds 120
}
cmdkey /add:TERMSRV/$LabNetworkBase.20 /user:$LabAdminUser@$LabDomainName /pass:$LabAdminPassword
mstsc /v:$LabNetworkBase.20
