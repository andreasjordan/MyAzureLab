# Add the domain group SQLAdmins to the sysadmin server role to get access to the default instance as a domain user
$sql = @(
    'CREATE LOGIN [DOM\SQLAdmins] FROM WINDOWS'
    'ALTER SERVER ROLE sysadmin ADD MEMBER [DOM\SQLAdmins]'
)
$null = $sql | sqlcmd
