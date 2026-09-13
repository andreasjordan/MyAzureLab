$ErrorActionPreference = 'Continue'

Import-Module -Name AutomatedLab
Import-Lab -Name TestingDbatools -NoValidation
Stop-LabVM -All
while ((Get-VM).State -contains 'Running') {
    Start-Sleep -Seconds 10
}
