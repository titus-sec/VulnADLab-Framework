# Filter a wordlist containing strings to meet the requirements of the Active Directory password policy
# Filtered string matches these requirements: 
#   Uppercase characters of European languages (A through Z, with diacritic marks, Greek and Cyrillic characters)
#   Lowercase characters of European languages (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
#   Base 10 digits (0 through 9)
#   Nonalphanumeric characters: ~!@#$%^&*_-+=`|\(){}[]:;”‘<>,.?/


# Reference: https://www.checkyourlogs.net/active-directory-password-complexity-check-powershell-mvphour/

Function FilterPasswords(){
    $wordlist = Get-Content -Path "$PSScriptRoot\21krockyou.txt"
    # Create a file (and directory) for created groups 
    New-Item -Path "$PSScriptRoot\filteredWordlist.txt" -ItemType File -Force | Out-Null
    Write-Host "A text file containing Group details will be created in $PSScriptRoot directory"
    
    $wordlist | ForEach-Object {
        if (($_ -cmatch "[A-Z\p{Lu}\s]") `
        -and ($_ -cmatch "[a-z\p{Ll}\s]") `
        -and ($_ -match "[\d]") `
        -and ($_ -match "[^\w]") `
        -and ($_.Length -gt 7)) {
            Add-Content -Path "$PSScriptRoot\filteredWordlist.txt" "$_" 
        }
    }
    $wordlistLength = $wordlist.Length
    Write-Host "Imported $wordlistLength passwords." -ForegroundColor Yellow

    $filteredWordlistLength = (Get-Content -Path "$PSScriptRoot\filteredWordlist.txt").Length
    
    Write-Host "Filtered (AD compliant) passwords: $filteredWordlistLength" -ForegroundColor Green
}

FilterPasswords