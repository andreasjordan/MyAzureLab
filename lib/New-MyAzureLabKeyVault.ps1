function New-MyAzureLabKeyVault {
    # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/winrm
    # https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate

    [CmdletBinding()]
    Param(
        [switch]$EnableException
    )

    process {
        $roleAssignmentParam = @{
            ResourceGroupName  = $resourceGroupName
            SignInName         = $context.Account.Id
            RoleDefinitionName = 'Key Vault Administrator'
        }
        $keyVaultParam = @{
            ResourceGroupName            = $resourceGroupName
            Location                     = $location
            VaultName                    = "KeyVault$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
            EnabledForDeployment         = $true
            EnabledForTemplateDeployment = $true
        }
        $certificatePolicyParams = @{
            SecretContentType = "application/x-pkcs12"
            SubjectName       = "CN=lab.local"
            IssuerName        = "Self"
            ValidityInMonths  = 12
            ReuseKeyOnRenewal = $true
        }
        $certificateName = "$($resourceGroupName.Replace('_',''))Certificate"

        try {
            Write-PSFMessage -Level Verbose -Message 'Testing assignment of Key Vault Administrator role'
            $roleAssignment = Get-AzRoleAssignment @roleAssignmentParam
            if (-not $roleAssignment) {
                Write-PSFMessage -Level Verbose -Message 'Assigning Key Vault Administrator role'
                $roleAssignment = New-AzRoleAssignment @roleAssignmentParam
            }

            Write-PSFMessage -Level Verbose -Message 'Testing KeyVault'
            $keyVault = Get-AzKeyVault -ResourceGroupName $resourceGroupName
            if (-not $keyVault) {
                Write-PSFMessage -Level Verbose -Message 'Creating KeyVault'
                $keyVault = New-AzKeyVault @keyVaultParam
            } else {
                $keyVaultParam.VaultName = $keyVault.VaultName
            }

            Write-PSFMessage -Level Verbose -Message 'Testing SelfSignedCertificate'
            $certificate = Get-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName
            if (-not $certificate) {
                Write-PSFMessage -Level Verbose -Message 'Creating SelfSignedCertificate'
                $certificatePolicy = New-AzKeyVaultCertificatePolicy @certificatePolicyParams
                $certificate = Add-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName -CertificatePolicy $certificatePolicy
            }

            # Waiting for secret to be ready
            while (1) {
                try {
                    $null = Get-AzKeyVaultSecret -VaultName $keyVaultParam.VaultName -Name $certificateName
                    break
                } catch {
                    Start-Sleep -Seconds 10
                }
            }
            
            Write-PSFMessage -Level Verbose -Message 'KeyVault is ready'
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
