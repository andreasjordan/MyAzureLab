$ErrorActionPreference = 'Stop'

Import-Module -Name PSFramework -Verbose:$false

Write-PSFMessage -Level Verbose -Message 'Importing PowerShell-Modules Az.Accounts, Az.Resources, Az.Network, Az.KeyVault, Az.Compute'
Import-Module -Name Az.Accounts, Az.Resources, Az.Network, Az.KeyVault, Az.Compute -Verbose:$false

Write-PSFMessage -Level Verbose -Message 'Importing PowerShell-Module Posh-SSH'
Import-Module -Name Posh-SSH -MinimumVersion 3.1.3 -Verbose:$false

if (Test-Path -Path $PSScriptRoot\MyAzureLabEnvironment.ps1) {
    Write-PSFMessage -Level Verbose -Message 'Importing local configuration'
    . $PSScriptRoot\MyAzureLabEnvironment.ps1
}

Write-PSFMessage -Level Verbose -Message 'Getting Azure context'
$context = Get-AzContext
if ($context) {
    if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription -and $context.Account.Id -eq $Env:MyAzureAccountId -and $context.Subscription.Name -eq $Env:MyAzureSubscription) {
        Write-PSFMessage -Level Verbose -Message "Already connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
    } elseif ($Env:MyAzureAccountId -and $Env:MyAzureSubscription) {
        Write-PSFMessage -Level Host -Message "Currently connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
        $message = "Switching to account '$($Env:MyAzureAccountId)' and subscription '$($Env:MyAzureSubscription)'"
        if ($Env:MyAzureTenant) {
            $message += " in tenant '$($Env:MyAzureTenant)'"
        }
        Write-PSFMessage -Level Host -Message $message
        $accountParams = @{
            AccountId    = $Env:MyAzureAccountId
            Subscription = $Env:MyAzureSubscription
        }
        if ($Env:MyAzureTenant) {
            $accountParams.Tenant = $Env:MyAzureTenant
        }
        $null = Connect-AzAccount @accountParams
    } else {
        Write-PSFMessage -Level Verbose -Message "Connected to Azure with account '$($context.Account.Id)' and subscription '$($context.Subscription.Name)' in tenant '$($context.Tenant.Id)'"
    }
} else {
    if ($Env:MyAzureAccountId -and $Env:MyAzureSubscription) {
        $message = "Connecting to account '$($Env:MyAzureAccountId)' and subscription '$($Env:MyAzureSubscription)'"
        if ($Env:MyAzureTenant) {
            $message += " in tenant '$($Env:MyAzureTenant)'"
        }
        Write-PSFMessage -Level Host -Message $message
        $accountParams = @{
            AccountId    = $Env:MyAzureAccountId
            Subscription = $Env:MyAzureSubscription
        }
        if ($Env:MyAzureTenant) {
            $accountParams.Tenant = $Env:MyAzureTenant
        }
        $null = Connect-AzAccount @accountParams
    } else {
        Stop-PSFFunction -Message 'Not connected to Azure. As $Env:MyAzureAccountId and $Env:MyAzureSubscription are not set, we stop here' -EnableException $true
    }
}

foreach ($file in (Get-ChildItem -Path $PSScriptRoot\lib\*-*.ps1)) {
    . $file.FullName
}
