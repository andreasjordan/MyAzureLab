$ErrorActionPreference = 'Continue'

Import-Module -Name AutomatedLab
Remove-Lab -Name TestingDbatools -Confirm:$false
Get-NetNat -Name TestingDbatools -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
