# dot-source library
#
# $PSScriptRoot - directory from which the script module is being executed.
#
. "$PSScriptRoot\Scripts\Deploy-Lab.ps1"
. "$PSScriptRoot\Scripts\Deploy-ADFunctions.ps1"
. "$PSScriptRoot\Scripts\Create-ADUsers.ps1"
. "$PSScriptRoot\Scripts\Create-ADGroups.ps1"
. "$PSScriptRoot\Scripts\Invoke-Misconfigurations.ps1"
. "$PSScriptRoot\Scripts\Invoke-Mitigations.ps1"

$WelcomeMessage = @"
,_ o
/ //\,
 \>> |
  \\,                
Author: Titus Saunorius a.k.a @titus-sec
Version: alpha-0.1
"@

Clear-Host
Write-Host "$WelcomeMessage" -ForegroundColor Blue

# Install Hyper-V and its relevant modules with PowerShell
Get-HyperV

# Install and configure AutomatedLab
Get-AutomatedLab

# Start deploying the lab
Invoke-LabDeployment

# Import the Lab
Import-CreatedLab

# Add random AD Groups
Write-Host "[=========================== Adding Domain Groups! ===========================]" -ForegroundColor Blue
Add-LabADGroups $labDCName

# Add random AD Users
Write-Host "[=========================== Adding Domain Users! ===========================]" -ForegroundColor Blue
Add-LabADUsers $labDCName

# Clone AD Domain Administrator
Write-Host "[=========================== Cloning Domain Administrator! ===========================]" -ForegroundColor Blue
Invoke-AdministratorUserClone $labDCName

# Add a Service Account as a Domain Administrator
Write-Host "[=========================== Adding Service Account! ===========================]" -ForegroundColor Blue
Invoke-ServiceAccount $labDCName

Write-Host "[=========================== Adding Domain Users as Remote Desktop Users on $labClient1Name and $labClient2Name! ===========================]" -ForegroundColor Blue
Invoke-ADUsersAsRemoteDesktopUsers $labClient1Name $labClient2Name

# Assign random domain users as Local Administrators on both client machines
Write-Host "[=========================== Adding Local Administrators on $labClient1Name! ===========================]" -ForegroundColor Blue
Invoke-LocalAdministrators $labClient1Name
Write-Host "[=========================== Adding Local Administrators on $labClient2Name! ===========================]" -ForegroundColor Blue
Invoke-LocalAdministrators $labClient2Name
Write-Host "[=========================== Adding Identical Local Administrator on $labClient1Name and $labClient2Name! ===========================]" -ForegroundColor Blue
Invoke-LocalAdministratorOnBothClients $labClient1Name $labClient2Name


Write-Host "[=========================== Adding a GPO to Disable Windows Defender and Windows Firewall! ===========================]" -ForegroundColor Magenta
Invoke-DisableWindowsDefenderAndWindowsFirewall

Write-Host "[=========================== Adding SMB Shares on each lab machine! ===========================]" -ForegroundColor Magenta
$labMachines | ForEach-Object {Invoke-SMBShare $_}
Write-Host "[=========================== Enable Windows HomeGroup on all lab machines! ===========================]" -ForegroundColor Magenta
$labMachines | ForEach-Object {Enable-HomeGroup $_}

Write-Host "[=========================== Configuring AD DS Certification Authority ===========================]" -ForegroundColor Magenta
Invoke-LDAPS

Write-Host "*** Would you like to allow LLMNR Poisoning attacks?***" -ForegroundColor Blue
Write-Host "> Enter 'Yes' to allow LLMNR Poisoning attacks" -ForegroundColor Red
Write-Host "> Enter 'No' to prevent LLMNR Poisoning attacks" -ForegroundColor Green
Write-Host "
>: " -NoNewline -ForegroundColor Blue
$mitigation = Read-Host 
if ($mitigation -eq "No") {
  Write-Host "[=========================== Disabling NBT-NS and Adding a GPO to Disable LLMNR! ===========================]" -ForegroundColor Magenta
  Invoke-DisableLLMNRAndNBT-NS
}


Write-Host "*** Would you like to allow SMB Relay attacks?***" -ForegroundColor Blue
Write-Host "> Enter 'Yes' to allow SMB Relay attacks" -ForegroundColor Red
Write-Host "> Enter 'No' to prevent SMB Relay attacks" -ForegroundColor Green
Write-Host "
>: " -NoNewline -ForegroundColor Blue
$mitigation = Read-Host 
if ($mitigation -eq "No") {
  Write-Host "[=========================== Enabling SMB Signing! ===========================]" -ForegroundColor Magenta
  $labMachines | ForEach-Object {Invoke-EnableSMBSigning $_}
}

Write-Host "*** Would you like to allow IPv6 attacks?***" -ForegroundColor Blue
Write-Host "> Enter 'Yes' to allow IPv6 attacks" -ForegroundColor Red
Write-Host "> Enter 'No' to prevent IPv6 attacks" -ForegroundColor Green
Write-Host "
>: " -NoNewline -ForegroundColor Blue
$mitigation = Read-Host 
if ($mitigation -eq "No") {
  Write-Host "[=========================== Disabling IPv6! ===========================]" -ForegroundColor Magenta
  $labMachines | ForEach-Object {Invoke-DisableIPv6 $_}
}


Write-Host "*** Would you like to allow Local Privilege Escalation attack (AlwaysInstallElevated)?***" -ForegroundColor Blue
Write-Host "> Enter 'Yes' to allow" -ForegroundColor Red
Write-Host "> Enter 'No' to prevent" -ForegroundColor Green
Write-Host "
>: " -NoNewline -ForegroundColor Blue
$mitigation = Read-Host 
if ($mitigation -eq "Yes") {
  Write-Host "[=========================== Enabling AlwaysInstallElevated! ===========================]" -ForegroundColor Magenta
  Invoke-EnableAlwaysInstallElevated
}

Write-Host "*** Would you like to install a vulnerable FTPShellClient 6.70 on Client1?***" -ForegroundColor Blue
Write-Host "> Enter 'Yes' to install" -ForegroundColor Red
Write-Host "> Enter 'No' to NOT install" -ForegroundColor Green
Write-Host "
>: " -NoNewline -ForegroundColor Blue
$mitigation = Read-Host 
if ($mitigation -eq "Yes") {
  Write-Host "[=========================== Installing FTPShellClient 6.70 on $labClient1Name! ===========================]" -ForegroundColor Magenta
  Write-Host "> Ignore any Path errors." -ForegroundColor Yellow
  Install-LabSoftwarePackage -ComputerName $labClient1Name -Path "$labSources\SoftwarePackages\FTPShellClient6.70_EnterpriseEdition.msi" -CommandLine '/quiet' -NoDisplay
}