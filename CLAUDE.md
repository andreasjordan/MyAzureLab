# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A personal collection of PowerShell scripts that build throwaway lab environments in Azure (Active Directory domains, SQL Server instances, Oracle, Docker database hosts, a Hyper-V/AutomatedLab host). It is deliberately *not* Terraform/Ansible: the author values being able to run only part of a script, so the scripts are written as "menus" to be executed line by line rather than as end-to-end automation.

There is no build, no test suite, no linter, and no module manifest. Everything is dot-sourced `.ps1`.

## Running the code

Requires **PowerShell 7** (the `init_*` scripts `throw` on `$PSVersionTable.PSVersion.Major -lt 7`) and the modules `PSFramework`, `Az.Accounts`, `Az.Resources`, `Az.Network`, `Az.KeyVault`, `Az.Compute`, `Posh-SSH` (>= 3.1.3).

Entry point is always dot-sourcing an init script **from the repo root**, because they contain the relative path `. .\MyAzureLab.ps1` and `. .\<Lab>\set_vm_config.ps1`:

```powershell
. .\init_SQLServerLabMini.ps1
. .\init_SQLServerLabMini.ps1 -StartComputerName DC, CLIENT -ConnectComputerName CLIENT
```

Dot-sourcing matters: the init script defines `$resourceGroupName`, `$location`, `$initCredential`, `$credentials`, `$vmConfig`, `$statusConfig`, `$domainConfig` in the caller's session, and the `*-MyAzureLab*` functions read several of them as ambient globals.

Every init script has a bare `break` roughly a third of the way down. Everything above it runs on dot-source (connect, show resource group state, optionally start VMs / open RDP); everything below is a catalogue of one-off snippets meant to be selected and run manually in the editor. **Code below the `break` is not dead code and is not expected to run top-to-bottom** — it includes destructive operations (`Remove-MyAzureLabVM -All`, `Remove-AzResourceGroup`) sitting next to setup snippets. Some of it is scratch/prose that would not even parse as a sequence.

`MyAzureLabEnvironment.ps1` (gitignored) holds the author's personal settings and is dot-sourced by `MyAzureLab.ps1`. See README.md for the variables; the important optional one is `$Env:MyStatusURL` — when unset, the labs deploy a throwaway `STATUS` VM instead and remove it at the end.

Running any of this creates billable Azure resources. Do not execute lab scripts unless explicitly asked.

## Architecture

### Three layers

1. **`MyAzureLab.ps1`** — bootstrap. Imports modules, loads `MyAzureLabEnvironment.ps1`, connects/switches the Azure context, resolves `$homeIP` from `ipinfo.io`, then dot-sources every `lib\*-*.ps1` (the `*-*` glob is what excludes `lib\status.ps1` from being loaded as a function).

2. **`lib\`** — the `*-MyAzureLab*` functions wrapping `Az` and `Posh-SSH`. Conventions used throughout:
   - `$resourceGroupName`, `$location`, `$context`, `$homeIP`, `$initCredential`, `$statusConfig`, `$domainConfig` are read from the caller's scope, **not** passed as parameters.
   - Every function takes `-EnableException` and reports failure via `Stop-PSFFunction -Message ... -EnableException $EnableException`; callers in the create_VMs scripts always pass `-EnableException`.
   - Logging is `Write-PSFMessage` (`-Level Host` for user-facing progress, `-Level Verbose` for steps).
   - Resource naming is positional, derived from a bare computer name: `<NAME>_VM`, `<NAME>_Disk1.vhd`, `<NAME>_Interface`, `<NAME>_PublicIP`. Functions convert between the two forms with `-replace '_VM$', ''` / string interpolation. Fixed names: `VirtualNetwork`, `NetworkSecurityGroup`, key vault `KeyVault<10 random digits>`, certificate `<ResourceGroupName minus underscores>Certificate`.
   - `DC` is special-cased in `New-MyAzureLabVM`: it gets a static private IP derived from the subnet prefix (`x.x.x.100`).

3. **Lab folders** (`SQLServerLab\`, `SQLServerLabMini\`, `OracleOnWin11\`, `DockerDatabases\`, `HyperVLab\`) — per-lab `set_vm_config.ps1` (data) plus `create_VMs.ps1` / `create_<NAME>.ps1` (orchestration).

### How a Windows-domain lab is deployed

`set_vm_config.ps1` builds an `[ordered]` `$vmConfig` hashtable keyed by computer name. Each entry carries both Azure facts (`SourceImage`, `VMSize`) and guest configuration (`Packages` for chocolatey, `Modules` for PSGallery, `Domain`, `Status`, `FileServer`, `SQLServer`, `DelegateComputer`) plus up to three script paths: `Script_A`, `Script_B`, `Script_C` (and `ScriptBlock_C`). `$statusConfig` and `$domainConfig` are shared `[PSCustomObject]` instances referenced by every VM entry, with `Uri` and `DCIPAddress` left `$null` and **mutated in place during Part 1** so all VMs see the resolved values.

`create_VMs.ps1` then runs the phases, and each phase does the same thing for every VM that defines that script slot:

```
Part 1  New-MyAzureLabVM per config entry, then resolve status URI + DC IP
Part 2  Invoke-MyAzureLabDeployment -Path Script_A   (Deployment_A.ps1 — everywhere)
Part 3  Invoke-MyAzureLabDeployment -Path Script_B   (DC only: fill file server)
Part 4  Invoke-MyAzureLabDeployment -Path Script_C   (CLIENT/SQL: install & configure SQL Server)
```

Between phases: `Start-Sleep -Seconds 120`, then `Wait-MyAzureLabDeploymentCompletion` polls the status API until every reporting host has posted the same final message.

### The deployment mechanism (important, non-obvious)

`Invoke-MyAzureLabDeployment -Path` does **not** run the script over the remote session. It opens a PSSession, writes the script text to `C:\Deployment\deployment.ps1` and the VM's config object as JSON to `C:\Deployment\config.txt`, registers a scheduled task `DeploymentAtStartup` running as `SYSTEM` at startup, and starts it once. This is what lets `Deployment\*.ps1` reboot the machine mid-run and resume where it left off.

Consequences that shape every script under `Deployment\`:

- They are **idempotent and restartable**. Every block is guarded by a state check (`if (-not (Get-Command choco ...))`, `if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ne 5)`, `if (-not (Test-Path ...))`) so that re-running after a reboot skips completed work.
- They run under Windows PowerShell 5.1 (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`), as `SYSTEM`, non-interactively — not pwsh 7.
- They read their own configuration from `$PSScriptRoot\config.txt`, not from parameters.
- `Restart-Computer -Force` followed by `return` is the idiom for "reboot and continue at next startup".
- Failure is signalled by `Send-Status` + `return`, never by throwing — a thrown exception would kill the task without telling anyone.
- The final act of a successful script is `Unregister-ScheduledTask -TaskName DeploymentAtStartup`, which is also the signal that the phase is done.
- Each defines its own local copy of `Send-Status` (they run standalone on the guest and cannot see `lib\`).

`Invoke-MyAzureLabDeployment -ScriptBlock` is the other mode: run a block directly in the session, no scheduled task, no reboot support.

`Deployment_A.ps1` is the shared "make this machine usable" script — CredSSP, WinRM HTTP listener, firewall groups, chocolatey + packages, NuGet/PSGallery + modules, then branches on `$env:COMPUTERNAME -eq 'DC'` to either promote a forest and build the file server or join the domain and add users to local groups.

### Status API

Guests report progress by POSTing `{IP, Host, Message}` to a status endpoint. Either a permanent server (`$Env:MyStatusURL`) or an Ubuntu VM named `STATUS` running `lib\status.ps1` — a bare `HttpListener` on port 80 keeping the last message per IP in a hashtable, serving JSON on `/status` and an HTML table on `/`. `Send-MyAzureLabStatus` is the host-side equivalent, reporting as `localhost` (which `Wait-MyAzureLabDeploymentCompletion` filters out).

### Connectivity model

Windows VMs are reached over WinRM HTTPS on 5986 with a self-signed cert from the lab key vault (`-SkipCACheck -SkipCNCheck -SkipRevocationCheck`, Negotiate). Linux VMs over SSH via Posh-SSH. The NSG only opens 22/3389/5986/80 to `$homeIP`; `Show-MyAzureLabResourceGroupInfo` runs on every dot-source of an init script and silently rewrites the NSG rules (and any Azure SQL firewall rule named `AllowHome`) when the current home IP no longer matches.

`Start-MyAzureLabRDP` stashes the credential with `cmdkey`, launches `mstsc`, waits for the window title to appear, then deletes the credential.

### Odd ones out

- **`HyperVLab\`** does not follow the deployment-script pattern. It creates a single large `BASE` VM with `New-MyAzureLabVM -AutomatedLab`, which installs Hyper-V and AutomatedLab inside it; `AlwaysOn_AG.ps1` / `TestingDbatools.ps1` are AutomatedLab lab definitions that run *on* that VM, not from the host.
- **`InProgress\`** is gitignored scratch work.
- **`lib\Invoke-MyAzureLabPart1.ps1`** is an older abstraction of Part 1 that no current `create_VMs.ps1` calls.

## Conventions to follow when editing

- Lab passwords (`P#ssw0rd`, `initialP#ssw0rd`) are hard-coded in config and init scripts on purpose — these are disposable labs. Do not "fix" them into secret management. Real secrets live in `MyAzureLabEnvironment.ps1`, which is gitignored.
- Comments and identifiers are English; a few older comments are German. "maschine" (sic) is the established spelling throughout messages — match surrounding text rather than correcting it piecemeal.
- Parameter splatting into `@{}` hashtables named `<thing>Param`/`<thing>Params` is the house style for `Az` calls.
