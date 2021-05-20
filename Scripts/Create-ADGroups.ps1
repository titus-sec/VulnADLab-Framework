Function Add-LabADGroups($labDCName) {
    # Invoke-Command to DC to create an OU for DEFAULT Security Groups
    Invoke-ADDefaultSecurityGroupsOU($labDCName);

    # Invoke-Command to DC to create an OU for MANUALLY CREATED Security Groups
    try {
        Invoke-ADSecurityGroupOU($labDCName);
    } catch {
        Write-Host "    ******** Invoke-Command error when adding an OU for Groups! ********" -ForegroundColor Red
    }

    $groupNumber = 2..7 | Get-Random;
    Write-Host "    ******** Adding $groupNumber Groups! ********" -ForegroundColor Blue

    # Create a file (and directory) for created groups 
    New-Item -Path "$labPath\DeployedLabDetails\CreatedGroups.txt" -ItemType File -Force | Out-Null
    Write-Host "A text file containing created AD Group details will be created in $labPath\DeployedLabDetails directory"

    for ($num = 1 ; $num -le $groupNumber ; $num++){
        # Fetch a grup naem from a collection of group names
        $groupName = Get-Content -Path ".\Scripts\GroupTemplates\RoleGroups.txt" | Get-Random

        ## instantiate TextInfo object for converting strings to Title Case (for DisplayName)
        $textInfo = (Get-Culture).TextInfo
        $displayName = $textInfo.ToTitleCase($groupName.ToLower())

        # Add a description
        $description = "This is a group for $displayName."

        if (Select-String -Path "$labPath\DeployedLabDetails\CreatedGroups.txt" -Pattern "$groupName" -SimpleMatch) {
            # Group exists, do NOT create $groupName
            Write-Host "        *** Group name '$groupName' has already been created. Generating another group.. ***" -ForegroundColor Magenta
        } else {
        # Group doesn't exist, create $groupName
        
        # Invoke-Command to DC
        Invoke-RandomLabADGroup $labDCName $groupName $displayName $description

        Write-Host "            - Adding Group #$num ***" -ForegroundColor Yellow
        Write-Host "            - Name: $groupname ***" -ForegroundColor Yellow  
        }
    }
}
Function Add-RandomLabADGroup($groupName, $displayName, $description)
{
    $NewGroupParameters = @{
        'Name' = "$groupName"
        'GroupCategory' = 'Security'
        'DisplayName' = $displayName
        'GroupScope' = 'Global'
        'Description' = $description
    }
    try {
        $OU = Get-ADOrganizationalUnit -Filter {Name -eq 'SecurityGroups'}
        New-ADGroup @NewGroupParameters -Path $OU
    }
     catch {
        Write-Host "        *** Error occurred when adding a Group. Ignore if the script does not break. ***" -ForegroundColor Red
    }
}
Function Invoke-RandomLabADGroup($computerName, $groupName, $displayName, $description)
{
    try {
        Invoke-LabCommand -ActivityName 'New Random Group' -ScriptBlock {
            Param($groupName,  $displayName, $description)
            Add-RandomLabADGroup $groupName $displayName $description 
        } -ComputerName $computerName -Variable name,displayname,desc -Function (Get-Command Add-RandomLabADGroup) -NoDisplay -PassThru -ArgumentList $groupName, $displayName, $description
        
        # Write the created group to a text file
        Add-Content -Path "$labPath\DeployedLabDetails\CreatedGroups.txt" "$groupName"     
    }
    catch {
        Write-Host "        *** Invoke-Command error occurred when adding a Group. number ***" -ForegroundColor Red
    }
}
Function Invoke-ADDefaultSecurityGroupsOU($computerName)
{
    try {
        Invoke-LabCommand -ActivityName 'Create a Default Security Group OU' -ScriptBlock {
            try {
                New-ADOrganizationalUnit -Name 'DefaultSecurityGroups' -Description 'This is an Organizational Unit made for Default Security Groups' -ProtectedFromAccidentalDeletion $False -ErrorAction SilentlyContinue  
            } catch {
                # OU exists
                Write-Host "        *** 'Default Security Groups' OU has already been created. ***" -ForegroundColor Yellow
            }
    
            $CNUsers = Get-ADObject -Filter {Name -eq 'Users' -and ObjectClass -eq 'container'}
            $OU = Get-ADOrganizationalUnit -Filter {Name -eq 'DefaultSecurityGroups'}
    
            Get-ADGroup -SearchBase $CNUsers.DistinguishedName -Filter * | ForEach-Object {
                Move-ADObject -Identity $_ -TargetPath $OU.DistinguishedName -ErrorAction SilentlyContinue
            } 
    
        } -ComputerName $computerName -NoDisplay -PassThru
    } catch {
        Write-Host "    ******** Invoke-Command error when adding an OU for Groups! ********" -ForegroundColor Red
    }
}
Function Invoke-ADSecurityGroupOU($computerName)
{
    Invoke-LabCommand -ActivityName 'Create a SecurityGroups OU' -ScriptBlock {
        try {
            New-ADOrganizationalUnit -Name 'SecurityGroups' -Description 'This is an Organizational Unit made for created Groups' -ProtectedFromAccidentalDeletion $False -ErrorAction SilentlyContinue
        } catch {
            # OU exists
            Write-Host "        *** 'Security Groups' OU has already been created. ***" -ForegroundColor Yellow
        }
    } -ComputerName $computerName -NoDisplay -PassThru
}

