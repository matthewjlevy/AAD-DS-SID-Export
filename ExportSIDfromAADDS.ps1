# ----------------------------------------------------------------------------- 
# Script: ExportSIDfromAADDS.ps1 
# Version: 1.0
# Author: Matthew Levy 
# Date: 28/12/2020 
# Keywords: AD SID Export, CSV, NBConsult
# comments: matthew@NBConsult.co.za
# Email: support@nbconsult.co.za
# ----------------------------------------------------------------------------- 
<#
.Synopsis
   Export SID values for users supplied in a CSV file to a CSV file.
.DESCRIPTION
   The script exports the SID value for accounts gathered from a CSV file ()
    and logs information to a log file in the working directory. If you run this script as a scheduled task, you need to specify the credentials as an encrypted file.
    https://blogs.technet.microsoft.com/robcost/2008/05/01/powershell-tip-storing-and-using-password-credentials/
.EXAMPLE
   '.\ExportSIDfromAADDS.ps1' -SourceCSVFilePath C:\Temp\SageUsers.csv -UsersOU "OU=Disabled Users,DC=Contoso,DC=Com" -OutputCSV "OU=New Users,DC=Contoso,DC=Com" -ADServer "DC01"

.PARAMETER SourceCSVFilePath
 Specify the path or UNC path to the CSV source file. Mandatory Parameter. If there is no file in the path, the script will end. 
 If you don't specify a path, the script will ERROR:
 "Cannot bind argument to parameter 'Path' because it is an empty string."

.PARAMETER UsersOU
 Specify the Distinguished name (DN) of the OU in AAD DS where you want to query the values from. Mandatory.

.PARAMETER OutputCSV
 Specify the path or UNC path to the CSV output file. Mandatory Parameter.

.OUTPUTS
   Log file with date and time in the file name.
   Output CSV file

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
    $SourceCSVFilePath,
    [parameter(Mandatory = $True)]
    [alias("UserOU")]
    $UsersOU,
    [parameter(Mandatory = $True)]
    [alias("Export")]
    $OutputCSV
    )

$credentials = Get-Credential #If the script is set to run as a scheduled task you need to replace this with the secure password file process.

$dateObj = Get-Date
$Logfile = $PWD.Path + "\SIDExport_" + $dateObj.Year + $dateObj.Month + $dateObj.Day + $dateObj.Hour + $dateObj.Minute + $dateObj.Second + ".log"

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
If (Test-Path $SourceCSVFilePath) {
    $AIABizUsers = @(Import-Csv $SourceCSVFilePath)

    LogWrite ("Number of users in the CSV: " + $AIABizUsers.Count)

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
$adusers = Get-AdUser -Filter * -Properties name,samaccountname, userprincipalname, sid
$UserStats = @()

foreach ($user in $AIABizUsers) {
LogWrite -LogOnly "Processing $($user.Name), $($user.UserPrincipalName)"
    $AADDSUser = @()
    $AADDSUser = Get-ADUser -Filter "UserPrincipalName -eq '$($user.Userprincipalname)'" |Select SID, UserPrincipalName, SamAccountName
    if ($AADDSUser)
    {
            # Create a new instance of a .Net object

        $User = New-Object System.Object

        # Add user-defined customs members: the records retrieved with the three PowerShell commands

        $User | Add-Member -MemberType NoteProperty -Value $user.name -Name AIABizName
        $User | Add-Member -MemberType NoteProperty -Value $user.Samaccountname -Name LANID
        $User | Add-Member -MemberType NoteProperty -Value $AADDSUser.UserPrincipalName -Name AADDSUPN
        $User | Add-Member -MemberType NoteProperty -Value $AADDSUser.SID -Name AADDSSID

        # Add right hand operand to value of variable ($User) and place result in variable ($UserStats)

        $UserStats += $User
    }
    else
    {
            LogWrite -Err "        -AD User doesn't exsist or can't be found: $($user.Userprincipalname)"
    }
        }
}

 #region Disabled for testing
 <#
    foreach ($user in $AIABizUsers) {
        LogWrite -LogOnly "Processing $($user.EMPLID_0), $($user.NAM_0) $($user.SURNAME_0)"
        $UserManagerDN = $null
        $department = $null
        $office = $user.FCY_0
        switch ($office) {
            {[string]::IsNullOrEmpty($office)} {$office = "NotSet"; LogWrite "No Office value for $($user.EMPLID_0), setting Office attribute in AD to 'NotSet'"; break}
            {$office -ne $null} {LogWrite -Success "Office is not blank"}
        }
        $Title = $user.POSDES_0
        switch ($Title) {
            {[string]::IsNullOrEmpty($Title)} {$Title = "NotSet"; LogWrite "No Title value for $($user.EMPLID_0), setting Title attribute in AD to 'NotSet'"; break}
            {$Title -ne $null} {LogWrite -Success "Title is not blank"}
        }
        $contract = $user.CTRNUM_0
        switch ($contract) {
            {[string]::IsNullOrEmpty($contract)} {$contract = "NotSet"; LogWrite "No Contract value for $($user.EMPLID_0), setting Contract attribute in AD to 'NotSet'"; break}
            {$contract -ne $null} {LogWrite -Success "Contract is not blank"}
        }
        $contractType = $user.NATCON_0
        switch ($contractType) {
            {[string]::IsNullOrEmpty($contractType)} {$contractType = "NotSet"; LogWrite "No Contract Type value for $($user.EMPLID_0), setting EmployeeType attribute in AD to 'NotSet'"; break}
            {$contractType -ne $null} {LogWrite -Success "Contract Type is not blank"}
        }
        $Mobile = $user.MOBILE_0
        switch ($Mobile) {
            {[string]::IsNullOrEmpty($Mobile)} {$Mobile = "0"; LogWrite "No Mobile value for $($user.EMPLID_0), setting MobilePhone attribute in AD to '0'"; break}
            {$Mobile -ne $null} {LogWrite -Success "Mobile is not blank"}
        }
        Try {
            $UserManagerDN = Get-ADUser -Filter "SamAccountName -eq '$($user.CHEFCTR_0)'" -ErrorAction Stop
        }
        catch {
            LogWrite "No Manager value for $($user.EMPLID_0)"
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
                Move-ADObject  $disabeUser -TargetPath $UsersOU -Confirm:$false -Credential $credentials -ErrorAction Stop
                LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($UsersOU)"
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
                    Move-ADObject  $disabeUser -TargetPath $UsersOU -Confirm:$false -Credential $credentials -ErrorAction Stop
                    LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($UsersOU)"
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
                    Write-Host -ForegroundColor Yellow "Trying to update user from Line 205"
                    $department = $user.ETRSRV_0
                    switch ($department) {
                        '' {
                            Write-host -ForegroundColor Magenta "Setting user with no Department";
                            Set-ADUser $ADUser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $ADUser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                            LogWrite -Success "Updated $($ADUser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"; Break
                        }
                        {$department -ne $null} {
                            Write-host -ForegroundColor Green "Setting user with department value";
                            Set-ADUser $ADUser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Credential $credentials -ErrorAction Stop;
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
                    Write-Host -ForegroundColor Yellow "Trying to update user from Line 246"
                    $NonADuser = Get-ADUser $firlas -Credential $credentials -ErrorAction SilentlyContinue
                    $department = $user.ETRSRV_0
                    switch ($department) {
                        '' {
                            Write-host -ForegroundColor Magenta "Setting user with no Department";
                            Set-ADUser $NonADuser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Credential $credentials -ErrorAction Stop;
                            Set-ADUser $NonADuser -Replace @{AdminDescription = "PowerShell modified on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials;
                            Logwrite -Success "Found a user in AD $($NonADuser.SamAccountName) that matches the OLD username format of FIRLAS, updating details but not SamAccountName...";
                            LogWrite -Success "Updated $($NonADuser.DistinguishedName) details in AD";
                            $UpdatedUsersCount += 1;
                            LogWrite -LogOnly "-------------------------------------------------------------------------------"; Break
                        }
                        {$department -ne $null} {
                            Write-host -ForegroundColor Green "Setting user with department value";
                            Set-ADUser $NonADuser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Credential $credentials -ErrorAction Stop;
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
                        Write-Host -ForegroundColor Yellow "Creating new user from Line 273"
                        New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName -UserPrincipalName "$($user.EMPLID_0)@capeunionmart.co.za" -DisplayName $FirstName' '$LastName -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Path $OutputCSV -AccountPassword (ConvertTo-SecureString -AsPlainText 'vNW7b}[%|y2E' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                        Set-ADUser $User.EMPLID_0 -Replace @{AdminDescription = "PowerShell created on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                        LogWrite -Success "Created new user $($User.EMPLID_0) in $($OutputCSV)"
                        LogWrite -LogOnly "-------------------------------------------------------------------------------"
                        $NewUsersCount += 1
                    }
                    catch {
                        Logwrite -Err "Name already exists, appending character to mitigate duplication in the Name"
                        try {
                            Write-host -ForegroundColor Yellow "Creating new user from Line 283"
                            New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName' ('$($User.EMPLID_0)')' -UserPrincipalName "$($user.EMPLID_0)@capeunionmart.co.za" -DisplayName $FirstName' '$LastName' ('$($User.EMPLID_0)')' -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 -Manager $UserManagerDN -Office $office -employeeNumber $contract -MobilePhone $Mobile -Title $Title -Path $OutputCSV -AccountPassword (ConvertTo-SecureString -AsPlainText 'vNW7b}[%|y2E' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                            Set-ADUser $User.EMPLID_0 -Replace @{AdminDescription = "PowerShell created on $(Get-Date) from $($env:COMPUTERNAME)"; employeeType = "$contractType"} -Credential $credentials
                            LogWrite -Success "Created new user $firstname $LastName ($($User.EMPLID_0)) in $($OutputCSV)"
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
    Logwrite "Rows in CSV:       |$($AIABizUsers.Count)"
    LogWrite "$(Get-Date)"

#>
#endregion Disabled for testing
}

Else {
    Write-Host ""
    Write-Host "There's no user csv list to work with."
    Write-Host ""
}