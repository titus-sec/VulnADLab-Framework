Function Invoke-AdministratorUserClone($computerName)
{
    # Fetch a random domain user's sAM account name from a collection of created domain users
    $userSamAccountName = Get-Content -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" | Get-Random
    Write-Host "User $userSamAccountName is assigned to Domain Administrators Security Groups"

    try {
        Invoke-LabCommand -ActivityName 'Clone Administrator User' -ScriptBlock {
            Param($userSamAccountName)

            # Fetch Security Groups assigned to the default Administrator domain user
            $AdministratorGroups = (Get-ADUser -Identity Administrator -Properties MemberOf).MemberOf

            # Assign all fetched Default Administrator's Security Groups to a randomly selected domain user
            foreach ($SecurityGroup in $AdministratorGroups) { 
                Add-ADGroupMember -Identity $SecurityGroup -Members $userSamAccountName
            }
        } -ComputerName $computerName -NoDisplay -PassThru -Variable sAMAccountName -ArgumentList $userSamAccountName

    } catch {
        Write-Host " *** Invoke-Command error occurred when adding AD Security Groups to $userSamAccountName user. ***" -ForegroundColor Red
    }
}
Function Invoke-ServiceAccount($computerName)
{
    # Fetch a random service name
    $serviceName = Get-Content -Path '.\Scripts\UserTemplates\ServiceNames.txt' | Get-Random
    Write-Host "Service $serviceName is assigned to Domain Administrators Security Groups"
    # Write all created groups to a file
    Add-Content -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" "$serviceName"

    # Fetch a password from a 'bad' wordlist for cracking
    $password = Get-Content -Path ".\BonusScripts\filteredWordlist.txt" | Get-Random

    try {
        Invoke-LabCommand -ActivityName 'Add a Service Account' -ScriptBlock {
            Param($serviceName, $password, $labDCName, $labDomainName, $labDCObjectName)
            
            # Add a domain user for the service account
            New-ADUser `
                -Name "$serviceName"`
                -UserPrincipalName $serviceName `
                -SamAccountName "$serviceName" `
                -DisplayName $serviceName `
                -Description "This is $serviceName description." `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Enabled $True `
                -PasswordNeverExpires $True

            # Fetch Security Groups assigned to Administrator domain user
            $AdministratorGroups = (Get-ADUser -Identity Administrator -Properties MemberOf).MemberOf

            # Assign all Security Groups to a randomly selected domain user
            foreach ($SecurityGroup in $AdministratorGroups) { 
                Add-ADGroupMember -Identity $SecurityGroup -Members $serviceName
            }

            # Setting up the Service Account for Kerberoasting
            $arg1 = "$labDCName/$serviceName.$labDomainName"+":60111"
            $arg2 = "$labDCObjectName\$serviceName"
            setspn -a $arg1 $arg2

        } -ComputerName $computerName -NoDisplay -PassThru -Variable serviceName,password, DCname,DomainName,DCObjectName -ArgumentList $serviceName, $password, $labDCName, $labDomainName, $labDCObjectName
    } catch {
        Write-Host " *** Invoke-Command error occurred when assigning permissions to $serviceName service. ***" -ForegroundColor Red
    }
}
Function Invoke-LocalAdministrators($computerName)
{
    $localAdminNumber = 1..2 | Get-Random;
    Write-Host "    ******** Number of Local Administrators being added: $localAdminNumber! ********" -ForegroundColor Blue

    for ($num = 1 ; $num -le $localAdminNumber ; $num++){

        # Fetch a random user's sAM account name from a collection of created domain users
        $userSamAccountName = Get-Content -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" | Get-Random
        Write-Host "User $userSamAccountName is assigned to Local Administrators group" -ForegroundColor Yellow

        try {
            Invoke-LabCommand -ActivityName 'Clone Administrator User' -ScriptBlock {
                Param($userSamAccountName)

                # Assign Local Administrator Security Group to a randomly selected domain user
                Add-LocalGroupMember -Group "Administrators" -Member $userSamAccountName
            } -ComputerName $computerName -NoDisplay -PassThru -Variable sAMAccountName -ArgumentList $userSamAccountName

        } catch {
            Write-Host " *** Invoke-Command error occurred when assigning permissions to $userSamAccountName user. ***" -ForegroundColor Red
        }
    }
}
Function Invoke-LocalAdministratorOnBothClients($computerName, $computerName2)
{
    # Fetch a random domain user's sAM account name from a collection of created domain users
    $userSamAccountName = Get-Content -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" | Get-Random
    Write-Host "User $userSamAccountName is assigned to Local Administrators group for both - $computerName and $computerName2" -ForegroundColor Yellow

    try {
        # Assign the same domain user as a Local Administrator on both machines

        Invoke-LabCommand -ActivityName 'Clone Administrator User' -ScriptBlock {
            Param($userSamAccountName)

            # Assign Local Administrator Security Group to a randomly selected domain user
            Add-LocalGroupMember -Group "Administrators" -Member $userSamAccountName
        } -ComputerName $computerName -NoDisplay -PassThru -Variable sAMAccountName -ArgumentList $userSamAccountName

        Invoke-LabCommand -ActivityName 'Clone Administrator User' -ScriptBlock {
            Param($userSamAccountName)

            # Assign Local Administrator Security Group to a randomly selected domain user
            Add-LocalGroupMember -Group "Administrators" -Member $userSamAccountName
        } -ComputerName $computerName2 -NoDisplay -PassThru -Variable sAMAccountName -ArgumentList $userSamAccountName

    } catch {
        Write-Host " *** Invoke-Command error occurred when assigning permissions to $userSamAccountName user. ***" -ForegroundColor Red
    }
}


Function Invoke-ADUsersAsRemoteDesktopUsers($computerName, $computerName2)
{
    # Assign all domain users to a local group 'Remote Desktop Users' on both client machines
    try {
        Invoke-LabCommand -ActivityName 'Add domain users as Remote Desktop Users' -ScriptBlock {
            # Assign all domain users to a local group 'Remote Desktop Users' on Client 1
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member 'Domain Users'
        } -ComputerName $computerName -NoDisplay -PassThru

        Invoke-LabCommand -ActivityName 'Add domain users as Remote Desktop Users' -ScriptBlock {
            # Assign all domain users to a local group 'Remote Desktop Users' on Client 2
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member 'Domain Users'
        } -ComputerName $computerName2 -NoDisplay -PassThru

    } catch {
        Write-Host " *** Invoke-Command error occurred when adding domain users as Remote Desktop Users on both client machines.***" -ForegroundColor Red
    }
}

Function Invoke-DisableWindowsDefenderAndWindowsFirewall(){
    # Windows Defender and Windows Firewall are enabled by default
    
    # Create a Group Policy to disable Windows Defender and its real-time protection on all lab machines, as well as the Windows Firewall
        try {
            Invoke-LabCommand -ActivityName 'Create a GPO to Disable Windows Defender and Windows Firewall' -ScriptBlock {

                # Create a GPO
                New-GPO -Name "Disable Windows Defender and Windows Firewall" -Comment "Group Policy that disables Windows Defender and its real-time protection feature. Domain-wide. " | Out-Null

                # Configure registry-based policy settings in the created GPO
                
                # Disable Windows Defender
                Set-GPRegistryValue -Name "Disable Windows Defender and Windows Firewall" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWORD -Value 1 | Out-Null
                Set-GPRegistryValue -Name "Disable Windows Defender and Windows Firewall" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWORD -Value 1 | Out-Null            
                
                # Disable Windows Firewall
                Set-GPRegistryValue -Name "Disable Windows Defender and Windows Firewall" -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -Type DWORD -Value 0 | Out-Null            

                # Link the created GPO to the lab domain
                New-GPLink -Name "Disable Windows Defender and Windows Firewall" -Target ((Get-ADDomain).DistinguishedName) | Out-Null
    
            } -ComputerName $labDCName -NoDisplay -PassThru
            Write-Host "[=========================== Successfully created a GPO that disables Windows Defender Domain-wide! ===========================]" -ForegroundColor Green
    
        } catch {
            Write-Host " *** Invoke-Command error occurred when creating a GPO to disable Windows Defender and Windows Firewall***" -ForegroundColor Red
        }
}

Function Invoke-LDAPS()
{
    # Enable LDAPS on the server
    try {
        Invoke-LabCommand -ActivityName 'Enable LDAPS' -ScriptBlock {
            # Performs installation and configuration of the AD CS Certification Authority role service on the server
            Install-WindowsFeature Adcs-Cert-Authority -Restart 
            Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 99 -Force
        } -ComputerName $labDCName -NoDisplay -PassThru

    } catch {
        Write-Host " *** Invoke-Command error occurred when configuring AD DS Certification Authority***" -ForegroundColor Red
    }
}

Function Invoke-EnableAlwaysInstallElevated(){
    # Create a Group Policy to enable AlwaysInstallElevated permissions that allows for privilege escalation
    try {
        Invoke-LabCommand -ActivityName 'Create a GPO to EnableAlwaysInstallElevated' -ScriptBlock {

            # Create a GPO
            New-GPO -Name "Enable AlwaysInstallElevated" -Comment "Group Policy that disables LLMNR and NBT-NS. Domain-wide. " | Out-Null

            # Configure registry-based policy settings in the created GPO
            Set-GPRegistryValue -Name "Enable AlwaysInstallElevated" -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWORD -Value 1 | Out-Null
            Set-GPRegistryValue -Name "Enable AlwaysInstallElevated" -Key "HKCU\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWORD -Value 1 | Out-Null
            
            # Link the created GPO to the lab domain
            New-GPLink -Name "Enable AlwaysInstallElevated" -Target ((Get-ADDomain).DistinguishedName) | Out-Null

        } -ComputerName $labDCName -NoDisplay -PassThru
        Write-Host "[=========================== Successfully created a GPO that enables AlwaysInstallElevated Domain-wide! ===========================]" -ForegroundColor Green

    } catch {
        Write-Host " *** Invoke-Command error occurred when creating a GPO to enable AlwaysInstallElevated***" -ForegroundColor Red
    }
}