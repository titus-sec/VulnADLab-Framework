Function Invoke-DisableLLMNRAndNBT-NS(){
    # Enabled by default
    # Function that calls functions to disable NBT-NS and LLMNR on all machines

    # Disable NetBIOS over TCP/IP on all lab machines
    $labMachines | ForEach-Object{Invoke-DisableNBT-NS $_}

    # Create a Group Policy to disable LLMNR
    Invoke-DisableLLMNR    
}
Function Invoke-DisableNBT-NS($computerName){
    # Disable NBT-NS on all host interfaces as a prevention against LLMNR Poisoning Attacks
    try {
        Invoke-LabCommand -ActivityName 'Disable NBT-NS on all interfaces' -ScriptBlock {
            # Disable NetBIOS over TCP/IP on all network interfaces of the host
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2
            # Restart all network interfaces
            Restart-NetAdapter -Name "*"
            
        } -ComputerName $computerName -NoDisplay -PassThru
        Write-Host "[=========================== Successfully Disabled NBT-NS on $computerName! ===========================]" -ForegroundColor Green
    } catch {
        Write-Host " *** Invoke-Command error occurred when disabling NBT-NS on $computerName***" -ForegroundColor Red
    }
}
Function Invoke-DisableLLMNR(){
        # Create a Group Policy to disable LLMNR as a prevention against LLMNR Poisoning Attacks
        try {
            Invoke-LabCommand -ActivityName 'Create a GPO to Disable LLMNR' -ScriptBlock {

                # Create a GPO
                New-GPO -Name "Disable LLMNR" -Comment "Group Policy that disables LLMNR domain-wide." | Out-Null

                # Configure registry-based policy settings in the created GPO
                Set-GPRegistryValue -Name "Disable LLMNR" -Key "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWORD -Value 0 | Out-Null
                
                # Link the created GPO to the lab domain
                New-GPLink -Name "Disable LLMNR" -Target ((Get-ADDomain).DistinguishedName) | Out-Null
    
            } -ComputerName $labDCName -NoDisplay -PassThru
            Write-Host "[=========================== Successfully created a GPO that disables LLMNR Domain-wide! ===========================]" -ForegroundColor Green
    
        } catch {
            Write-Host " *** Invoke-Command error occurred when creating a GPO to disable LLMNR***" -ForegroundColor Red
        }
}
Function Invoke-EnableSMBSigning($computerName){
    # Disabled by default
    # Enable SMB signing as a prevention against SMB Relay Attacks
    try {
        Invoke-LabCommand -ActivityName 'Enable SMB Signing' -ScriptBlock {
            # Enable SMB Signing
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ -Name RequireSecuritySignature -Value 1
            
        } -ComputerName $computerName -NoDisplay -PassThru
        Write-Host "[=========================== Successfully Enabled SMB Signing on $computerName! ===========================]" -ForegroundColor Green
        } catch {
            Write-Host " *** Invoke-Command error occurred when enabling SMB Signing on $computerName***" -ForegroundColor Red
        }   
}
Function Invoke-DisableIPv6($computerName){
    # Enabled by default
    # Disable IPv6 as a prevention to IPv6 MiTM attacks
    try {
        Invoke-LabCommand -ActivityName 'Disable IPv6' -ScriptBlock {
            # Disable IPv6
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Name DisabledComponents -Value 255
            Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6
        } -ComputerName $computerName -NoDisplay -PassThru
        Write-Host "[=========================== Successfully Disabled IPv6 on $computerName! ===========================]" -ForegroundColor Green
        } catch {
            Write-Host " *** Invoke-Command error occurred when disabling IPv6 on $computerName***" -ForegroundColor Red
        }   
}