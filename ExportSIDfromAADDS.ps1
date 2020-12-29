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
   '.\ExportSIDfromAADDS.ps1' -SourceCSVFilePath C:\Temp\AIAUsers.csv -Domain "OU=Disabled Users,DC=Contoso,DC=Com" -OutputCSV "OU=New Users,DC=Contoso,DC=Com" -ADServer "DC01"

.PARAMETER SourceCSVFilePath
 Specify the path or UNC path to the CSV source file. Mandatory Parameter. If there is no file in the path, the script will end. 
 If you don't specify a path, the script will ERROR:
 "Cannot bind argument to parameter 'Path' because it is an empty string."

.PARAMETER Domain
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
    * Service Account Credentials with Read access to Active Directory.
   Enable-WindowsOptionalFeature -Online -FeatureName `
         RSATClient-Roles-AD-Powershell

#>

[CmdletBinding()]
Param(
    [parameter(Mandatory = $True)]
    [alias("Csv")]
    $SourceCSVFilePath,
    [parameter(Mandatory = $True)]
    [alias("FQDN")]
    $FQDN,
    [parameter(Mandatory = $True)]
    [alias("Export")]
    $OutputCSV
    )

$credentials = Get-Credential #If the script is set to run as a scheduled task you need to replace this with the secure password file process.

$dateObj = Get-Date
$Logfile = $PWD.Path + "\SIDExport_" + $dateObj.Year + $dateObj.Month + $dateObj.Day + $dateObj.Hour + $dateObj.Minute + $dateObj.Second + ".log"

function Get-Domain {
	
	#Retrieve the Fully Qualified Domain Name if one is not supplied
	# division.domain.root

	if ($FQDN -eq "") {
		[String]$fqdn = [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain()
	}

	# Create a New Array 'Item' for each item in between the '.' characters
	# Arrayitem1 division
	# Arrayitem2 domain
	# Arrayitem3 root
	$FQDNArray = $FQDN.split(".")
	
	# Add A Separator of ','
	$Separator = ","

	# For Each Item in the Array
	# for (CreateVar; Condition; RepeatAction)
	# for ($x is now equal to 0; while $x is less than total array length; add 1 to X
	for ($x = 0; $x -lt $FQDNArray.Length ; $x++)
		{ 

		#If it's the last item in the array don't append a ','
		if ($x -eq ($FQDNArray.Length - 1)) { $Separator = "" }
		
		# Append to $DN DC= plus the array item with a separator after
		[string]$DN += "DC=" + $FQDNArray[$x] + $Separator
		
		# continue to next item in the array
		}
	
	#return the Distinguished Name
	return $DN
}

$TargetDN = "OU=AADDC Users,"+(Get-Domain)
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
If (Test-Path $SourceCSVFilePath) 
 {
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
$UserStats = @()

foreach ($user in $AIABizUsers) {
LogWrite -LogOnly "Processing $($user.Name), $($user.UserPrincipalName)"
    $AADDSUser = @()
    $AADDSUser = Get-ADUser -Filter "UserPrincipalName -eq '$($user.Userprincipalname)'" -SearchBase $TargetDN -credential $credentials |Select SID, UserPrincipalName, SamAccountName
    if ($AADDSUser)
    {
            # Create a new instance of a .Net object

        $item = New-Object System.Object

        # Add user-defined customs members: the records retrieved with the three PowerShell commands

        $item | Add-Member -MemberType NoteProperty -Value $user.Name -Name AIABizName
        $item | Add-Member -MemberType NoteProperty -Value $user.Samaccountname -Name LANID
        $item | Add-Member -MemberType NoteProperty -Value $AADDSUser.UserPrincipalName -Name AADDSUPN
        $item | Add-Member -MemberType NoteProperty -Value $AADDSUser.SID -Name AADDSSID

        # Add right hand operand to value of variable ($item) and place result in variable ($UserStats)

        $UserStats += $item
    }
    else
    {
            LogWrite -Err "        -AD User doesn't exsist or can't be found: $($user.Userprincipalname)"
    }
        

        $UserStats | Export-Csv -Path $OutputCSV -NoTypeInformation
    }
}
Else {
    Write-Host ""
    Write-Host "There's no source user csv list to work with."
    Write-Host ""
}