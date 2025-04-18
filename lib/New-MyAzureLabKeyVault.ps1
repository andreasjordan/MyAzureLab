function New-MyAzureLabKeyVault {
    # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/winrm
    # https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate

    [CmdletBinding()]
    Param(
        [PSCredential]$Credential,
        [switch]$EnableException
    )

    process {
        $keyVaultParam = @{
            VaultName                    = "KeyVault$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
            EnabledForDeployment         = $true
            EnabledForTemplateDeployment = $true
            WarningAction                = "SilentlyContinue"  # Suppress warning about future changes
        }
        
        try {
            Write-PSFMessage -Level Verbose -Message 'Creating KeyVault'
            $null = New-AzKeyVault -ResourceGroupName $resourceGroupName -Location $location @keyVaultParam

            Write-PSFMessage -Level Verbose -Message 'Creating SelfSignedCertificate'
#            $certificatePolicy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=$($domainConfig.Name)" -IssuerName "Self" -ValidityInMonths 12 -ReuseKeyOnRenewal
            $certificatePolicy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=lab.local" -IssuerName "Self" -ValidityInMonths 12 -ReuseKeyOnRenewal
            $null = Add-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name "$($resourceGroupName.Replace('_',''))Certificate" -CertificatePolicy $certificatePolicy
            # Waiting for secret to be ready
            while (1) {
                try {
                    $null = Get-AzKeyVaultSecret -VaultName $keyVaultParam.VaultName -Name "$($resourceGroupName.Replace('_',''))Certificate"
                    break
                } catch {
                    Start-Sleep -Seconds 10
                }
            }
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
