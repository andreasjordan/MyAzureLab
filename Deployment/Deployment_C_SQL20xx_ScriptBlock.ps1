Param(
    [PSCustomObject]$Config
)

# Add the domain group SQLAdmins to the sysadmin server role to get access to the default instance as a domain user
$netbiosName = $Config.Domain.NetbiosName
$sql = @(
    "CREATE LOGIN [$netbiosName\SQLUsers] FROM WINDOWS"
    "CREATE LOGIN [$netbiosName\SQLAdmins] FROM WINDOWS"
    "ALTER SERVER ROLE sysadmin ADD MEMBER [$netbiosName\SQLAdmins]"
)
$null = $sql | sqlcmd
