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
            $roleAssignment = Invoke-MyAzureLabRetry -Activity 'Get-AzRoleAssignment' -ScriptBlock {
                Get-AzRoleAssignment @roleAssignmentParam
            }
            if (-not $roleAssignment) {
                Write-PSFMessage -Level Verbose -Message 'Assigning Key Vault Administrator role'
                $roleAssignment = Invoke-MyAzureLabRetry -Activity 'New-AzRoleAssignment' -ScriptBlock {
                    New-AzRoleAssignment @roleAssignmentParam
                }
            }

            Write-PSFMessage -Level Verbose -Message 'Testing KeyVault'
            $keyVault = Invoke-MyAzureLabRetry -Activity 'Get-AzKeyVault' -ScriptBlock {
                Get-AzKeyVault -ResourceGroupName $resourceGroupName
            }
            if (-not $keyVault) {
                Write-PSFMessage -Level Verbose -Message 'Creating KeyVault'
                $keyVault = Invoke-MyAzureLabRetry -Activity 'New-AzKeyVault' -ScriptBlock {
                    New-AzKeyVault @keyVaultParam
                }
            } else {
                $keyVaultParam.VaultName = $keyVault.VaultName
            }

            Write-PSFMessage -Level Verbose -Message 'Testing SelfSignedCertificate'
            $certificate = Invoke-MyAzureLabRetry -Activity 'Get-AzKeyVaultCertificate' -ScriptBlock {
                Get-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName
            }
            if (-not $certificate) {
                # New-AzKeyVaultCertificatePolicy only builds an object in memory, no retry needed
                Write-PSFMessage -Level Verbose -Message 'Creating SelfSignedCertificate'
                $certificatePolicy = New-AzKeyVaultCertificatePolicy @certificatePolicyParams
                $certificate = Invoke-MyAzureLabRetry -Activity 'Add-AzKeyVaultCertificate' -ScriptBlock {
                    Add-AzKeyVaultCertificate -VaultName $keyVaultParam.VaultName -Name $certificateName -CertificatePolicy $certificatePolicy
                }
            }

            # Waiting for secret to be ready
            # Get-AzKeyVaultSecret returns nothing if the secret does not exist yet, so test the result
            # and do not just wait for the command to no longer throw
            $waitUntil = [datetime]::Now.AddSeconds(300)
            while (-not (Get-AzKeyVaultSecret -VaultName $keyVaultParam.VaultName -Name $certificateName -ErrorAction SilentlyContinue)) {
                if ([datetime]::Now -ge $waitUntil) {
                    Stop-PSFFunction -Message "Timeout while waiting for the certificate $certificateName in key vault $($keyVaultParam.VaultName)" -EnableException $EnableException
                    return
                }
                Start-Sleep -Seconds 10
            }
            
            Write-PSFMessage -Level Verbose -Message 'KeyVault is ready'
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
