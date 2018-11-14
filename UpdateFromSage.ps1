# ----------------------------------------------------------------------------- 
# Script: UpdateFromSage.ps1 
# Version: 2.2
# Author: Matthew Levy 
# Date: 13/11/2018 
# Keywords: AD Update, CSV, NBConsult
# comments: NBConsult.co.za
# Email: support@nbconsult.co.za
# ----------------------------------------------------------------------------- 
<#
.Synopsis
   Update AD from a CSV file provided by Sage database.
.DESCRIPTION
   The script either Updates existing users accounts, create's new user accounts or disabled decommissioned accounts with information gathered from a CSV file ()
    and logs information to a log file in the working directory. If you run this script as a scheduled task, you need to specify the credentials as an encrypted file.
    https://blogs.technet.microsoft.com/robcost/2008/05/01/powershell-tip-storing-and-using-password-credentials/
.EXAMPLE
   '.\UpdateFromSage.ps1' -CSVfilePath C:\Temp\SageUsers.csv -DisabledOU "OU=Disabled Users,DC=Contoso,DC=Com" -NewUserOU "OU=New Users,DC=Contoso,DC=Com" -ADServer "DC01"

.PARAMETER CSVfilePath
 Specify the path or UNC path to the CSV source file. Mandatory Parameter. If there is no file in the path, the script will end. 
 If you don't specify a path, the script will ERROR:
 "Cannot bind argument to parameter 'Path' because it is an empty string."

.PARAMETER DisabledOU
 Specify the Distinguished name (DN) of the OU in AD where you want to move disabled users to. Mandatory.

.PARAMETER NewUserOU
 Specify the Distinguished name (DN) of the OU in AD where you want to CREATE new users. Mandatory.

.OUTPUTS
   Log file with date and time in the file name.
.NOTES
   Before running this script in Production Active Directory, test it in a Development environment!!
   It is strongly suggested that the script is run on a dedicated Windows machine that is a member of the domain, but NOT on a domain controller.
   Script tested on Windows 10.
   The script requirements 
    * Windows 10 or Windows Server 2012/2016 as a member of the Domain.
    * Active Directory PowerShell Module
    * Windows RSAT Hotfix.(KB2693643)
    * Service Account Credentials with Write access to Active Directory.
   Enable-WindowsOptionalFeature -Online -FeatureName `
         RSATClient-Roles-AD-Powershell

#>

[CmdletBinding()]
Param(
    [parameter(Mandatory = $True)]
    [alias("Csv")]
    $CSVfilePath,
    [parameter(Mandatory = $True)]
    [alias("DisableOu")]
    $DisabledOU,
    [parameter(Mandatory = $True)]
    [alias("NewOu")]
    $NewUserOU,
    [parameter(Mandatory = $True)]
    [alias("DomainController")]
    $ADServer)

$credentials = Get-Credential #If the script is set to run as a scheduled task you need to replace this with the secure password file process.

$dateObj = Get-Date
$Logfile = $PWD.Path + "\SageUpdate_" + $dateObj.Year + $dateObj.Month + $dateObj.Day + $dateObj.Hour + $dateObj.Minute + $dateObj.Second + ".log"

$DisabledCount = 0
$NewUsersCount = 0
$UpdatedUsersCount = 0
$FaileduserCount = 0


Function LogWrite {
    Param (
        [switch]$Err,
        [switch]$Success,
        [switch]$LogOnly,
        [string]$logstring
    
    )
   
    if ($LogOnly -eq $false) {
        if ($err) { 
            Write-Host -ForegroundColor Red $logstring
        }
        elseif ($success) {
            Write-Host -ForegroundColor Green $logstring
        }
        else {
            Write-Host $logstring
        } 
    }
   
    Add-content $Logfile -value $logstring
}

LogWrite (Get-Date)
If (Test-Path $CSVfilePath) {
    $SageUsers = @(Import-Csv $CSVfilePath)

    LogWrite ("Number of users in the CSV: " + $SageUsers.Count)

    LogWrite "Checking script environment..."
    LogWrite "Loading Active Directory PowerShell Module..."


    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        LogWrite -Success "AD Module exists"
        LogWrite -LogOnly "-------------------------------------------------------------------------------"
    }
    else {
        LogWrite -Err "AD Module does not exist. Please install ActiveDirectory PowerShell module"
        LogWrite -LogOnly "-------------------------------------------------------------------------------"
        Break
    }

    Import-Module ActiveDirectory

    foreach ($user in $SageUsers) {
        LogWrite -LogOnly "Processing $($user.EMPLID_0), $($user.NAM_0) $($user.SURNAME_0)"
        $UserManagerDN = $null
        $department = $null
        $office = $user.FCY_0
        switch ($office) {
            {[string]::IsNullOrEmpty($office)} {$office = "NotSet"; LogWrite -Err "No Office value for $($user.EMPLID_0), setting Office attribute in AD to 'NotSet'"; break}
            {$office -ne $null} {LogWrite -Success "Office is not blank"}
        }
        $Title = $user.POSDES_0
        switch ($Title) {
            {[string]::IsNullOrEmpty($Title)} {$Title = "NotSet"; LogWrite -Err "No Title value for $($user.EMPLID_0), setting Title attribute in AD to 'NotSet'"; break}
            {$Title -ne $null} {LogWrite -Success "Title is not blank"}
        }
        $contract = $user.CTRNUM_0
        switch ($contract) {
            {[string]::IsNullOrEmpty($contract)} {$contract = "NotSet"; LogWrite -Err "No Contract value for $($user.EMPLID_0), setting Contract attribute in AD to 'NotSet'"; break}
            {$contract -ne $null} {LogWrite -Success "Contract is not blank"}
        }
        $contractType = $user.NATCON_0
        switch ($contractType) {
            {[string]::IsNullOrEmpty($contractType)} {$contractType = "NotSet"; LogWrite -Err "No Contract Type value for $($user.EMPLID_0), setting EmployeeType attribute in AD to 'NotSet'"; break}
            {$contractType -ne $null} {LogWrite -Success "Contract Type is not blank"}
        }
        Try {
            $UserManagerDN = Get-ADUser -Filter "SamAccountName -eq '$($user.CHEFCTR_0)'" -ErrorAction Stop
        }
        catch {
            LogWrite -Err "No Manager value for $($user.EMPLID_0)"
        }
        
        if ($user.STA_0 -eq "R") {
            LogWrite "$($user.EMPLID_0) is flagged for deletion, disabling account in AD..."
            $firlas = $user.NAM_0.Substring(0, 3) + $user.SURNAME_0.Substring(0, 3)

            # Disables user if found using employee ID
            try {  
                $disabeUser = (Get-ADUser -Filter "SamAccountName -eq '$($user.EMPLID_0)'" -Credential $credentials -ErrorAction Stop)
                Set-ADUser $disabeUser -Enabled $false -Manager $UserManagerDN -Credential $credentials
                Set-ADUser $disabeUser -Replace @{AdminDescription = "PowerShell disabled on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                LogWrite "        - Disabled $($user.EMPLID_0)"
                Move-ADObject  $disabeUser -TargetPath $DisabledOU -Confirm:$false -Credential $credentials -ErrorAction Stop
                LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($DisabledOU)"
                LogWrite -LogOnly "-------------------------------------------------------------------------------"
                $DisabledCount += 1
            }
            catch {
                
                # Disables user if found using FirLas
                try {
                    $disabeUser = Get-ADUser $firlas -Credential $credentials -ErrorAction Stop
                    Set-ADUser $disabeUser -Enabled $false -Manager $UserManagerDN -Credential $credentials
                    Set-ADUser $disabeUser -Replace @{AdminDescription = "PowerShell disabled on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                    LogWrite "        - Disabled $($disabeUser.SamAccountName)"
                    Move-ADObject  $disabeUser -TargetPath $DisabledOU -Confirm:$false -Credential $credentials -ErrorAction Stop
                    LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($DisabledOU)"
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                    $DisabledCount += 1
                }
                catch {
                    LogWrite -Err "        -AD User doesn't exsist or can't be found: $($user.EMPLID_0)"
                    LogWrite -LogOnly "        -Skipping $($user.EMPLID_0)"
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                    $FaileduserCount += 1
                }
            }
      
      
        }

        #   Sets an existing user's details
        else {
            $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($user.EMPLID_0)'" -Credential $credentials
            if ($user.EMPLID_0 -eq $ADUser.SamAccountName) {
                LogWrite "User: $($ADUser.SamAccountName) ($($ADUser.GivenName) $($ADUser.Surname)) matches: $($user.EMPLID_0). Updating Details..."
                try {
                    Write-Host -ForegroundColor Yellow "Trying to update user from Line 200"
                    $department = $user.ETRSRV_0
                    switch ($department) {
                        '' {
                            Write-host -ForegroundColor Magenta "Setting user with no Department";
                            Set-ADUser $ADUser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $ADUser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                            LogWrite -Success "Updated $($ADUser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"; Break
                        }
                        {$department -ne $null} {
                            Write-host -ForegroundColor Green "Setting user with department value";
                            Set-ADUser $ADUser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $ADUser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                            LogWrite -Success "Updated $($ADUser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"
                        }
    
                    }
                    
                    
                }
                catch { 
                    LogWrite -Err "        -Unable to update user in AD: $($user.EMPLID_0). Consult the log file $($Logfile)"
                    LogWrite -LogOnly "        -$($Error.Item(0).categoryInfo)"
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                    $FaileduserCount += 1
                }
        
        
                    
            }
    
            #  Sets an existing AD users found with FirLas account naming convention
            else {
                $NonADuser = @()
                $firlas = $user.NAM_0.Substring(0, 3) + $user.SURNAME_0.Substring(0, 3)
                try {
                    Write-Host -ForegroundColor Yellow "Trying to update user from Line 236"
                    $NonADuser = Get-ADUser $firlas -Credential $credentials -ErrorAction SilentlyContinue
                    $department = $user.ETRSRV_0
                    switch ($department) {
                        '' {
                            Write-host -ForegroundColor Magenta "Setting user with no Department";
                            Set-ADUser $NonADuser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $NonADuser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials;
                            Logwrite -Success "Found a user in AD $($NonADuser.SamAccountName) that matches the OLD username format of FIRLAS, updating details but not SamAccountName...";
                            LogWrite -Success "Updated $($NonADuser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"; Break
                        }
                        {$department -ne $null} {
                            Write-host -ForegroundColor Green "Setting user with department value";
                            Set-ADUser $NonADuser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $NonADuser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials;
                            Logwrite -Success "Found a user in AD $($NonADuser.SamAccountName) that matches the OLD username format of FIRLAS, updating details but not SamAccountName...";
                            LogWrite -Success "Updated $($NonADuser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"
                        }
                            
                    }
                }
                catch {}
                if (!($NonADuser)) {
                    $firstname = $user.NAM_0
                    $LastName = $user.SURNAME_0
                    
                    # Creates New User
                    try {
                        Write-Host -ForegroundColor Yellow "Creating new user from Line 263"
                        New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName -UserPrincipalName "$($user.EMPLID_0)@capeunionmart.co.za" -DisplayName $FirstName' '$LastName -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Path $NewUserOU -AccountPassword (ConvertTo-SecureString -AsPlainText 'vNW7b}[%|y2E' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                        Set-ADUser $User.EMPLID_0 -Replace @{AdminDescription = "PowerShell created on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                        LogWrite -Success "Created new user $($User.EMPLID_0) in $($NewUserOU)"
                        LogWrite -LogOnly "-------------------------------------------------------------------------------"
                        $NewUsersCount += 1
                    }
                    catch {
                        Logwrite -Err "Name already exists, appending character to mitigate duplication in the Name"
                        try {
                            Write-host -ForegroundColor Yellow "Creating new user from Line 273"
                            New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName' ('$($User.EMPLID_0)')' -UserPrincipalName "$($user.EMPLID_0)@capeunionmart.co.za" -DisplayName $FirstName' '$LastName' ('$($User.EMPLID_0)')' -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -Title $Title -Path $NewUserOU -AccountPassword (ConvertTo-SecureString -AsPlainText 'vNW7b}[%|y2E' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                            Set-ADUser $User.EMPLID_0 -Replace @{AdminDescription = "PowerShell created on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                            LogWrite -Success "Created new user $firstname $LastName ($($User.EMPLID_0)) in $($NewUserOU)"
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"
                            $NewUsersCount += 1
                        }
                        catch {
                            LogWrite -Err "        -Unable to add user in AD: $($user.EMPLID_0). Consult the log file $($Logfile)"
                            LogWrite -LogOnly "        -$($Error.Item(0).categoryInfo)"
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"
                            $FaileduserCount += 1
                        }
                    }
                }
        
            }
        }  
    }


    LogWrite "Disabled Users:    |$($DisabledCount)"
    Logwrite "New Users:         |$($NewUsersCount)"
    Logwrite "Updated Users:     |$($UpdatedUsersCount)"
    Logwrite "Failed Users:      |$($FaileduserCount)"
    Logwrite "Rows in CSV:       |$($SageUsers.Count)"
    LogWrite "$(Get-Date)"
}
Else {
    Write-Host ""
    Write-Host "There's no user csv list to work with."
    Write-Host ""
}