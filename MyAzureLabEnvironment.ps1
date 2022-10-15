$Env:MyAzureAccountId    = 'my@mydom.com'
$Env:MyAzureSubscription = 'The name of the subscription'

$Env:MyAzureDomainName      = 'test.local'        # First part in upper cases will be used as NetBiosName
$Env:MyAzureInitialAdmin    = 'aSecretName'       # Will be used when creating the virtual maschines
$Env:MyAzureInitialPassword = 'aSecretPassword'   # Will be used when creating the virtual maschines and for the certificate
$Env:MyAzurePassword        = 'aSimplerPassword'  # Will be used when creating additional users
