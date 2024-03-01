# Create firewall rule based on source code of dbatools (https://github.com/dataplat/dbatools/blob/development/public/New-DbaFirewallRule.ps1)
$ruleParams = @{
    DisplayName = 'SQL Server default instance'
    Name        = 'SQL Server default instance'
    Group       = 'SQL Server'
    Enabled     = 'True'
    Direction   = 'Inbound'
    Protocol    = 'TCP'
    LocalPort   = '1433'
}
$null = New-NetFirewallRule @ruleParams

# Add the domain group SQLAdmins to the sysadmin server role to get access to the default instance as a domain user
$sql = @(
    'CREATE LOGIN [DOM\SQLAdmins] FROM WINDOWS'
    'ALTER SERVER ROLE sysadmin ADD MEMBER [DOM\SQLAdmins]'
)
$null = $sql | sqlcmd
