# ----------------------------------------------------------------------------- 
# Script: UpdateFromSage.ps1 
# Author: Matthew Levy 
# Date: 07/20/2018 11:32:38 
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
    }
    else {
        LogWrite -Err "AD Module does not exist. Please install ActiveDirectory PowerShell module"
        Break
    }

    Import-Module ActiveDirectory

    foreach ($user in $SageUsers) {
        if ($user.STA_0 -eq "R") {
            LogWrite "$($user.EMPLID_0) is flagged for deletion, disabling account in AD..."
            $firlas = $user.NAM_0.Substring(0, 3) + $user.SURNAME_0.Substring(0, 3)

            try {  
                $disabeUser = (Get-ADUser -Filter "SamAccountName -eq $($user.EMPLID_0)" -ErrorAction Stop)
                Set-ADUser $disabeUser -Enabled $false
                LogWrite "        - Disabled $($user.EMPLID_0)"
                Move-ADObject  $disabeUser -TargetPath $DisabledOU -Confirm:$false -ErrorAction Stop
                LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($DisabledOU)"
                $DisabledCount += 1
            }
            catch {
                try {
                    $disabeUser = Get-ADUser $firlas -ErrorAction Stop
                    Set-ADUser $disabeUser -Enabled $false
                    LogWrite "        - Disabled $($disabeUser.SamAccountName)"
                    Move-ADObject  $disabeUser -TargetPath $DisabledOU -Confirm:$false -ErrorAction Stop
                    LogWrite "        - Moved AD user $($disabeUser.DistinguishedName) to $($DisabledOU)"
                    $DisabledCount += 1
                }
                catch {
                    LogWrite -Err "        -AD User doesn't exsist or can't be found: $($user.EMPLID_0)"
                    LogWrite -LogOnly "        -Skipping $($user.EMPLID_0)"
                    $FaileduserCount += 1
                }
            }
      
      
        }
  
        else {
            $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($user.EMPLID_0)'"
            if ($user.EMPLID_0 -eq $ADUser.SamAccountName) {
                LogWrite "User: $($ADUser.SamAccountName) ($($ADUser.GivenName) $($ADUser.Surname)) matches: $($user.EMPLID_0). Updating Details..."
                try {
                    Set-ADUser $ADUser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -ErrorAction Stop
                    LogWrite -Success "Updated $($ADUser.DistinguishedName) details in AD"
                    $UpdatedUsersCount += 1
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                }
                catch { 
                    LogWrite -Err "        -Unable to update user in AD: $($user.EMPLID_0). Consult the log file $($Logfile)"
                    LogWrite -LogOnly "        -$($Error.Item(0))"
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                    $FaileduserCount += 1
                }
        
        
                    
            }
     
            else {
                $NonADuser = @()
                $firlas = $user.NAM_0.Substring(0, 3) + $user.SURNAME_0.Substring(0, 3)
                try {
                    $NonADuser = Get-ADUser $firlas -ErrorAction SilentlyContinue
                    Set-ADUser $NonADuser -EmployeeID $user.EMPLID_0 -GivenName $User.NAM_0 -Surname $user.SURNAME_0 -Department $user.ETRSRV_0 -ErrorAction Stop
                    Logwrite -Success "Found a user in AD $($NonADuser.SamAccountName) that matches the OLD username format of FIRLAS, updating details but not SamAccountName..."
                    LogWrite -Success "Updated $($NonADuser.DistinguishedName) details in AD"
                    $UpdatedUsersCount += 1
                    LogWrite -LogOnly "-------------------------------------------------------------------------------"
                }
                catch {}
                if (!($NonADuser)) {
                    $firstname = $user.NAM_0
                    $LastName = $user.SURNAME_0
                    try {
                        New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName -DisplayName $FirstName' '$LastName -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 <# -OtherAttributes @{'extensionAttribute5' = "User Created by PowerShell Script on $($env:COMPUTERNAME)"} #> -Path $NewUserOU -AccountPassword (ConvertTo-SecureString -AsPlainText '53cr3tP@ssw0rd' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                        LogWrite -Success "Created new user $($User.EMPLID_0) in $($NewUserOU)"
                        LogWrite -LogOnly "-------------------------------------------------------------------------------"
                        $NewUsersCount += 1
                    }
                    catch {
                        Logwrite -Err "Name already exists, appending character to mitigate duplication in the Name"
                        try {
                            New-ADUser -SamAccountName $User.EMPLID_0 -Name $firstname' '$LastName' ('$($User.EMPLID_0)')' -DisplayName $FirstName' '$LastName' ('$($User.EMPLID_0)')' -GivenName $firstname -Surname $LastName -EmployeeID $user.EMPLID_0 -Department $user.ETRSRV_0 <# -OtherAttributes @{'extensionAttribute5' = "User Created by PowerShell Script on $($env:COMPUTERNAME)"} #> -Path $NewUserOU -AccountPassword (ConvertTo-SecureString -AsPlainText '53cr3tP@ssw0rd' -Force) -Enabled $False -Server $ADServer -Credential $credentials -ErrorAction stop
                        }
                        catch {
                            LogWrite -Err "        -Unable to add user in AD: $($user.EMPLID_0). Consult the log file $($Logfile)"
                            LogWrite -LogOnly "        -$($Error.Item(0))"
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