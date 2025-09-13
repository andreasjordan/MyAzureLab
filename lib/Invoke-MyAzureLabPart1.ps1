function Invoke-MyAzureLabPart1 {
    [CmdletBinding()]
    Param (
        [PSCredential]$InitialCredential,
        [hashtable]$Config,
        [switch]$EnableException
    )

    process {
        try {
            ##########
            Write-PSFMessage -Level Host -Message 'Part 1: Setting up the virtual maschines'
            ##########

            #####
            Write-PSFMessage -Level Host -Message 'Step 1: Setting up main infrastructure'
            #####

            if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
                Write-PSFMessage -Level Host -Message "Resource group $resourceGroupName already exists."
                if (Get-AzResource -ResourceGroupName $resourceGroupName) { 
                    Stop-PSFFunction -Message "Resource group $resourceGroupName is not empty exists. Stopping."
                }
            } else {
                Write-PSFMessage -Level Host -Message "Creating resource group $resourceGroupName"
                $null = New-AzResourceGroup -Name $resourceGroupName -Location $location
            }

            Write-PSFMessage -Level Host -Message 'Getting HomeIP'
            $homeIP = (Invoke-WebRequest -Uri "http://ipinfo.io/json" -UseBasicParsing | ConvertFrom-Json).ip
            if ($homeIP -notmatch '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
                Stop-PSFFunction -Message 'Failed to get IPv4 home IP. Stopping.' -Target $homeIP -EnableException $EnableException
            }

            Write-PSFMessage -Level Host -Message 'Creating key vault and certificate'
            New-MyAzureLabKeyVault -EnableException

            Write-PSFMessage -Level Host -Message 'Creating network and security group'
            New-MyAzureLabNetwork -HomeIP $homeIP -EnableException

            #####
            Write-PSFMessage -Level Host -Message 'Step 2: Setting up virtual maschines'
            #####

            # See https://azureprice.net/ to get a suitable vm size 
            foreach ($computerName in $Config.Keys) {
                Write-PSFMessage -Level Host -Message "Creating virtual maschine $computerName"
                New-MyAzureLabVM -ComputerName $computerName -SourceImage $config.$computerName.Azure.SourceImage -VMSize $config.$computerName.Azure.VMSize -Credential $InitialCredential -EnableException
            }

            #####
            Write-PSFMessage -Level Host -Message 'Step 3: Setting up deployment monitoring'
            #####

            Write-PSFMessage -Level Host -Message 'Configuring virtual maschine STATUS'
            Set-MyAzureLabSFTPItem -ComputerName STATUS -Credential $InitialCredential -Path $PSScriptRoot\..\MyLab\status.ps1 -Destination "/home/$($InitialCredential.UserName)" -Force -EnableException
            $installStatusApi = @(
                "sudo timedatectl set-timezone $($Config.STATUS.Timezone)"
                "echo '@reboot sudo pwsh /home/$($InitialCredential.UserName)/status.ps1 &' > /tmp/crontab"
                'crontab /tmp/crontab'
                'rm /tmp/crontab'
                "nohup sudo pwsh /home/$($InitialCredential.UserName)/status.ps1 &"
            )
            $null = Invoke-MyAzureLabSSHCommand -ComputerName STATUS -Credential $InitialCredential -Command $installStatusApi -EnableException
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
