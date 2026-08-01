Param(
    [PSCustomObject]$Config
)

$ErrorActionPreference = 'Stop'

# Add the domain group SQLAdmins to the sysadmin server role to get access to the default instance as a domain user.
# The statements are written so that running them again does not fail.
$netbiosName = $Config.Domain.NetbiosName
$sql = @(
    "IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N'$netbiosName\SQLUsers')"
    "    CREATE LOGIN [$netbiosName\SQLUsers] FROM WINDOWS"
    "IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N'$netbiosName\SQLAdmins')"
    "    CREATE LOGIN [$netbiosName\SQLAdmins] FROM WINDOWS"
    "IF NOT EXISTS (SELECT * FROM sys.server_role_members AS roleMember"
    "               JOIN sys.server_principals AS role ON role.principal_id = roleMember.role_principal_id"
    "               JOIN sys.server_principals AS member ON member.principal_id = roleMember.member_principal_id"
    "               WHERE role.name = 'sysadmin' AND member.name = N'$netbiosName\SQLAdmins')"
    "    ALTER SERVER ROLE sysadmin ADD MEMBER [$netbiosName\SQLAdmins]"
)

# -b is needed, without it sqlcmd returns exit code 0 even if the statements failed
$result = $sql | sqlcmd -b
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create the logins for $netbiosName, sqlcmd returned exit code $($LASTEXITCODE): $result"
}
