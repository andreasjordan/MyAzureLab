# MyAzureLab
Scripts to setup my labs in Microsoft Azure

## MyAzureLab.ps1

This holds all my wrapper commands that help me to setup parts of the environments.

## MyAzureLabEnvironment.ps1

This holds environment variables with my personl settings. That's why this part of .gitignore and you have to change that file on your local system.

## create_MultiDB.ps1

This Skript will setup my lab with Azure virtual maschines for the multi database environment based on docker.

It uses code from my repo [PowerShell-for-DBAs](..\PowerShell-for-DBAs\README.md).

## create_FailoverCluster.ps1

This Skript will setup my lab with Azure virtual maschines to test SQL Server instances in a Windows Failover Cluster.

The code to setup the failover cluster will be published soon...

