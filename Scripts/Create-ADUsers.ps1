Function Add-LabADUsers($labDCName) {
    $userNumber = 3..10 | Get-Random;
    Write-Host "    ******** Adding $userNumber Users! ********" -ForegroundColor Blue

    # Create a file (and directory) for created users 
    New-Item -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" -ItemType File -Force | Out-Null
    Write-Host "A text file containing created AD User details will be created in $labPath\DeployedLabDetails directory"

    for ($num = 1 ; $num -le $userNumber ; $num++){
        # Fetch a group name from a collection of created group names
        $groupName = Get-Content -Path "$labPath\DeployedLabDetails\CreatedGroups.txt" | Get-Random

        # Randomize user's gender
        $gender = 0,1 | Get-Random
        if ($gender -eq 0) {
            # Fetch a male first name from a collection of male names
            $givenName = Get-Content -Path ".\Scripts\UserTemplates\500malenamesUS.txt" | Get-Random
        } else {
            # Fetch a female first name from a collection of female names
            $givenName = Get-Content -Path '.\Scripts\UserTemplates\500femalenamesUS.txt' | Get-Random
        }
        
        # Fetch a last name first name from a collection of female names
        $surname = Get-Content -Path '.\Scripts\UserTemplates\500familynamesUS.txt' | Get-Random

        # Generate a sAM account name, its length must be less than 20
        $samAccountName = $givenName.substring(0,1) + '.' + $surname
        if ($samAccountName.Length -gt 20) {
             $samAccountName = $samAccountName.Substring(0,20)
        }

        # Generate a random password
        $password = Get-RandomPassword

        # Add a description
        $description = Get-RandomDescription

        # instantiate TextInfo object for converting strings to Title Case (for DisplayName)
        $textInfo = (Get-Culture).TextInfo
        $displayName = $textInfo.ToTitleCase($givenName.ToLower()) + $textInfo.ToTitleCase($surname.ToLower())

        Write-Host "            - Adding User #$num ***" -ForegroundColor Yellow
        Write-Host "            - Name: $givenName $surname ***" -ForegroundColor Yellow
        Write-Host "            - pw: $password ***" -ForegroundColor Yellow

        # Invoke to DC
        Invoke-RandomLabADUser $labDCName $givenName $surname $samAccountName $displayName $description $password $groupName
    }
    Write-Host "            - Your Domain User Login $samAccountName ***" -ForegroundColor Green
    Write-Host "            - Your Domain User Password $password ***" -ForegroundColor Green
}
Function Get-RandomPassword(){
    $passwordFromWordlistChance = 70
    $passwordChance = 1..100 | Get-Random;

    # $chance % user's password is grabbed from a wordlist, e.g., rockyou
    if ($passwordChance -gt $passwordFromWordlistChance) {
        $password = Get-Content -Path ".\BonusScripts\filteredWordlist.txt" | Get-Random
    } else {
        $password =  ("!@#$%^&*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[7..16] -join ''
    }    
    return $password
}

Function Get-RandomDescription(){
    #Include in description?
    $isPasswordInDescription = 1..100 | Get-Random;
    
    $descriptionIncludesPasswordChance = 70

    # $chance % user's password is not included in their description
    if ($isPasswordInDescription -gt $descriptionIncludesPasswordChance) {
        $description = 'Often forgets password.. Password is:' + $password
    } else {
        $description = ''
    }
    return $description
}
Function Add-RandomLabADUser($givenName, $surname, $samAccountName, $displayName, $description, $password, $groupName)
{
    $NewUserParameters = @{
        'Name' = $givenName + $surname
        'UserPrincipalName' = $givenName + $surname
        'SamAccountName' = "$samAccountName"
        'DisplayName' = $displayName
        'GivenName' = "$givenName"
        'Surname' = $surname
        'Description' = $description
        'AccountPassword' = (ConvertTo-SecureString $password -AsPlainText -Force)
        'Enabled' = $true
        'PasswordNeverExpires' = $true
    }
    try {
         New-ADUser @NewUserParameters
         Add-ADGroupMember -Identity $groupName -Members $samAccountName
     } catch {
        Write-Host "        *** Error occurred when adding a User. Ignore if the script does not break. ***" -ForegroundColor Red
    }
}
Function Invoke-RandomLabADUser($computerName, $givenName, $surname, $samAccountName, $displayName, $description, $password, $groupName)
{
    try {
        Invoke-LabCommand -ActivityName 'New Random User' -ScriptBlock {
            Param($givenName, $surname, $samAccountName, $displayName, $description, $password, $groupName)
            Add-RandomLabADUser $givenName $surname $samAccountName $displayname $description $password $groupName
        } -ComputerName $computerName -Variable name,lastname,samname,display,desc,password,groupname -Function (Get-Command Add-RandomLabADUser) -NoDisplay -PassThru -ArgumentList $givenName, $surname, $samAccountName, $displayName, $description, $password, $groupName    
        # Write the created user to a text file
        Add-Content -Path "$labPath\DeployedLabDetails\CreatedUsers.txt" "$samAccountName"
    } catch {
        Write-Host "        *** Invoke-Command error occurred when adding a user. number ***" -ForegroundColor Red
    }
}

