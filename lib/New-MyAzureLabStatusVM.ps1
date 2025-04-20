function New-MyAzureLabStatusVM {
    [CmdletBinding()]
    Param(
        [switch]$EnableException
    )

    process {
        try {
            Write-PSFMessage -Level Verbose -Message 'Creating virtual maschine STATUS'
            New-MyAzureLabVM -ComputerName STATUS -SourceImage Ubuntu22 -VMSize Standard_B2s -Credential $initCredential -EnableException
            Write-PSFMessage -Level Verbose -Message 'Configuring virtual maschine STATUS'
            Set-MyAzureLabSFTPItem -ComputerName STATUS -Credential $initCredential -Path $PSScriptRoot\status.ps1 -Destination "/home/$($initCredential.UserName)" -Force -EnableException
            $installStatusApi = @(
                "sudo timedatectl set-timezone $timezone"
                "echo '@reboot sudo pwsh /home/$($initCredential.UserName)/status.ps1 &' > /tmp/crontab"
                'crontab /tmp/crontab'
                'rm /tmp/crontab'
            )
            $null = Invoke-MyAzureLabSSHCommand -ComputerName STATUS -Credential $initCredential -Command $installStatusApi -EnableException
            Restart-MyAzureLabVM -ComputerName STATUS -EnableException
            
            $statusApiPrivateIP = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "STATUS_Interface").IpConfigurations[0].PrivateIpAddress
            $statusConfig.Uri = "http://$statusApiPrivateIP/status"
            $domainConfig.DCIPAddress = (Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name "DC_Interface").IpConfigurations[0].PrivateIpAddress
        } catch {
            Stop-PSFFunction -Message 'Failed' -ErrorRecord $_ -EnableException $EnableException
        }
    }
}
