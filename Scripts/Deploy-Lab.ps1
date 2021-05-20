$HelloMessage = @"
> Hello!

> In order to deploy the lab, you will have to specify a few settings.
> These include:
1. A disk drive for the lab and AutomatedLab's LabSources folder
2. The name of the lab and directory name for storing the lab files, including VM files
3. A lab domain name
4. A lab network switch name
5. Lab's Domain Controller name
6. Lab's Client 1 name
7. Lab's Client 2 name

> These will be prompted one by one.

"@
Write-Host "$HelloMessage" -ForegroundColor Yellow

## Disk drive to be used for creating the Lab
$labDrive = 'C:' # Default Value
Write-Host "> Enter a disk drive for storing VM files in a format of '{Drive Letter}:'" -ForegroundColor Blue
Get-PSDrive -PSProvider FileSystem
Write-Host "
Examples:
>: C:
>: D:" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green 
$labDrive = Read-Host
Write-Host "> Specified disk drive name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labDrive" -ForegroundColor Green 

## LabSources folder path
$labSources = "$labDrive\LabSources" 

# The name of the Lab and the Virtual Machine folder
$labName = "MyLab" # Default Value
Write-Host "
> Enter the name of the lab and directory name for storing Lab files, including the VM files.
> Only A-Z, a-z and 0-9 are allowed. 
> Please keep it simple to avoid errors.
Examples:
>: MyLab
>: HackingVulnerableLab" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green
$labName = Read-Host
Write-Host "> Specified lab name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labName" -ForegroundColor Green 

# Create the folder path for the lab using Join-Path
$labPath = Join-Path -Path $labDrive -ChildPath $labName

# Create the VM path for Virtual Machines
$vmPath = Join-Path -Path $labPath -ChildPath 'VMs'

# Domain Name
$labDomainName = "mydomain.local" # Default Value
Write-Host "
> Enter the lab domain name.
> Please keep it simple to avoid errors.
Examples:
>: mydomain.local
>: test.com" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green
$labDomainName = Read-Host
Write-Host "> Specified lab domain name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labDomainName" -ForegroundColor Green 


# Network Switch name
$labNetworkName = "myLabNetworkSwitch" # Default Value
Write-Host "
> Enter the lab's network switch name.
> Please keep it simple to avoid errors.
Examples:
>: myLabNetworkSwitch
>: LabSwitch" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green
$labNetworkName = Read-Host
Write-Host "> Specified lab's network switch name name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labNetworkName" -ForegroundColor Green 


# Domain Controller Name
$labDCName = "myLab-DC" # Default Value
Write-Host "
> Enter the lab's Domain Controller name.
> Please keep it simple to avoid errors.
Examples:
>: myLab-DC
>: test-DC" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green
$labDCName = Read-Host
Write-Host "> Specified lab's Domain Controller name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labDCName" -ForegroundColor Green 


# Client 1 Name
$labClient1Name = "Client1" # Default Value
Write-Host "
> Enter the lab's Client 1 name.
> Please keep it simple to avoid errors.
Examples:
>: Client1
>: BobMachine" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green
$labClient1Name = Read-Host
Write-Host "> Specified lab's Client 1 name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labClient1Name" -ForegroundColor Green 


# Client 2 Name
$labClient2Name = "Client2" # Default Value
Write-Host "
> Enter the lab's Client 2 name.
> Please keep it simple to avoid errors.
Examples:
>: Client2
>: AliceMachine" -ForegroundColor Blue
Write-Host "
>: " -NoNewline -ForegroundColor Green 
$labClient2Name = Read-Host
Write-Host "> Specified lab's Client 2 name: " -NoNewline -ForegroundColor Yellow
Write-Host "$labClient2Name" -ForegroundColor Green 

$labMachines = @($labDCName, $labClient1Name, $labClient2Name)

# Get the name for Domain's AD Objects used for AD Object paths
$labDCObjectName = $labDomainName.Substring(0, $labDomainName.IndexOf('.'))
$labDCObjectDomain = $labDomainName.Substring($labDomainName.IndexOf('.') + 1)

# Create a file (and directory) for assigned IPs 
New-Item -Path "$labPath\DeployedLabDetails\LabMachineIPv4Addresses.txt" -ItemType File -Force | Out-Null
Write-Host "A text file containing Lab Machine IPv4 Addresses will be created in $labPath\DeployedLabDetails\ directory"

Function Get-RandomIP($computerName){
    # Generate an array of possible IPv4 Addresses
    [System.Collections.ArrayList]$IPs = 1..254 | ForEach-Object {"192.168.77.$_"}
    
    # Randomly select an IPv4 Address from the created collection of IPv4 Addresses
    $randIP = $IPs | Get-Random

    # Remove the randomly selected IP from the array of available IPv4 Addresses
    while ($IPs -contains $randIP) {
        $IPs.Remove($randIP)
    }

    # Write assigned Ipv4 Address to a file
    Add-Content -Path "$labPath\DeployedLabDetails\LabMachinesIPv4Addresses.txt" "$randIP # $computerName assigned IPv4 Address"

    # Return a randomly selected IPv4 address
    return $randIP
}

# Lab Machine IPs - assign random IPv4 addresses
$labDCMachineIP = Get-RandomIP "Domain Controller"
$labClient1MachineIP = Get-RandomIP $labClient1Name
$labClient2MachineIP = Get-RandomIP $labClient2Name

Function Get-HyperV(){
    # Install Hyper-V and its relevant modules with PowerShell, the following command may be run with elevated privileges (Run as Administrator) if not enabled:
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -eq "Disabled"){
        Write-Host "*** $('Microsoft-Hyper-V') is Missing - Installing.. Might need to Reboot Windows. ***" -ForegroundColor Red
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
    } else {
    Write-Host "*** $('Microsoft-Hyper-V') is already Installed! ***" -ForegroundColor Green
    }
}
Function Get-AutomatedLab(){
    # Enable Windows PowerShell remoting settings to allow connection to the lab machines using AutomatedLab
    Enable-LabHostRemoting -Force -NoDisplay

    if (Get-Module -ListAvailable -Name AutomatedLab) {
        Write-Host "*** Automated Lab Module exists ***" -ForegroundColor Green
        # Download the lab sources content to the specified location
        New-LabSourcesFolder -Drive $labDrive.Substring(0,1)
    } else {
        Write-Host "*** Automated Lab Module does NOT exist ***" -ForegroundColor Red
        Write-Host "*** Attempting to install AutomatedLab module.. ***" -ForegroundColor Yellow
        
        try {
            # Install AutomatedLab module
            Install-Module -Name AutomatedLab -AllowClobber
            # Download the lab sources content to the specified location and overwrite any existing files
            New-LabSourcesFolder -Drive $labDrive.Substring(0,1) -Force
        }
        catch {
            Write-Host "*** An error occurred when installing AutomatedLab module. Please try importing it manually by running Import-Module -Name AutomatedLab -AllowClobber***" -ForegroundColor Red
        }
    }

    Write-Host "*** Available Operating Systems (placed into"$labSources"\ISOs) ***" -ForegroundColor Blue
    # Retrieve the available operating system versions the placed ISO files contain
    Get-LabAvailableOperatingSystem -Path $labSources\ISOs

    # Create the target directory if it does not exist
    if (-not (Test-Path $labPath)) { 
        New-Item $labPath -ItemType Directory | Out-Null
    }
}

Function Invoke-LabDeployment(){
    # Defining the Lab
    New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV -VmPath $vmPath

    # Adding ISOs to the Lab
    Add-LabIsoImageDefinition -Name WindowsServer -Path G:\LabSources\ISOs\WINDOWSSERVER.iso
    Add-LabIsoImageDefinition -Name WindowsClient -Path G:\LabSources\ISOs\WINDOWSENTERPRISE.iso

    # Defining the Network
    Add-LabVirtualNetworkDefinition -Name $labNetworkName -AddressSpace 192.168.77.0/24

    # Defining the Active Directory Domain and the Domain administrator account
    Add-LabDomainDefinition -Name $labDomainName -AdminUser administrator -AdminPassword Password1

    # Setting the Installation Credentials for all lab machines
    Set-LabInstallationCredential -Username Install -Password Password1

    # Defining the lab machines' default parameter values
    $PSDefaultParameterValues = @{
        'Add-LabMachineDefinition:Network' = $labNetworkName
        'Add-LabMachineDefinition:DomainName' = $labDomainName
        'Add-LabMachineDefinition:IsDomainJoined'= $true
        'Add-LabMachineDefinition:DNSServer1' = $labDCMachineIP
        'Add-LabMachineDefinition:Memory' = 2GB
        'Add-LabMachineDefinition:OperatingSystem' = 'Windows 10 Enterprise Evaluation'
        'Add-LabMachineDefinition:ToolsPath' = "$labSources\Tools"
    }

    # Add a Domain Controller
    Add-LabMachineDefinition -Name $labDCName -IpAddress $labDCMachineIP -Roles RootDC -OperatingSystem 'Windows Server 2019 Standard Evaluation (Desktop Experience)' -Memory 4GB

    # Add client machines
    Add-LabMachineDefinition -Name $labClient1Name -IpAddress $labClient1MachineIP
    Add-LabMachineDefinition -Name $labClient2Name -IpAddress $labClient2MachineIP

    # Install the lab
    Install-Lab

    # Export the lab definitions
    Export-LabDefinition -ExportDefaultUnattendedXml –Force

    # Display the time taken to deploy the lab
    Show-LabDeploymentSummary -Detailed
}
Function Invoke-SMBShare($computerName){
    # Add a randomly named SMB share on a host machine

    $shareName = Get-Content -Path ".\Scripts\OtherTemplates\SecretNames.txt" | Get-Random
    Write-Host "SMB Share $shareName is created on $computerName machine (Default Settings)." -ForegroundColor Yellow

    try {
        Invoke-LabCommand -ActivityName 'Add an SMB Share' -ScriptBlock {
            Param($shareName)
            New-Item "C:\$shareName" -type directory | Out-Null
            New-SmbShare -Name $shareName -Path "C:\$shareName" -FullAccess "Administrator" | Out-Null
        } -ComputerName $computerName -NoDisplay -PassThru -Variable shareName -ArgumentList $shareName
    } catch {
        Write-Host " *** Invoke-Command error occurred when adding an SMB share on $computerName ***" -ForegroundColor Red
    }
}
Function Enable-HomeGroup($computerName){
    try {
        Invoke-LabCommand -ActivityName 'Add an SMB Share' -ScriptBlock {
            # Enable Automatic Startup of Function Discovery Provider Host service
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost\ -Name Start -Value 2
            # Enable Automatic Startup of Function Discovery Resource Publication service
            Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub\ -Name Start -Value 2
        } -ComputerName $computerName -NoDisplay -PassThru
    } catch {
        Write-Host " *** Invoke-Command error occurred when enabling HomeGroup on $computerName ***" -ForegroundColor Red
    }
}
Function Import-CreatedLab(){
    # Import the Lab
    if((Get-Lab).Name -eq $labName){
        Write-Host "*** Lab"$labName" has been imported! ***" -ForegroundColor Green
    } else {
        Write-Host "*** Lab"$labName" is not imported! ***" -ForegroundColor Red
        Write-Host "*** Attempting to import the Lab.. ***" -ForegroundColor Yellow
        Import-Lab -Name $labName -NoDisplay
        if ((Get-Lab).Name -eq $labName){
            Write-Host "*** Lab"$labName" was successfully imported! ***" -ForegroundColor Green
        } else {
            Write-Host "*** Something went wrong. Attempt to import the Lab failed. ***" -ForegroundColor Red
        }
    }
}
