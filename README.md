# Introduction 
UpdateFromSage.ps1
Update AD from a CSV file provided by Sage database.

The script either Updates existing users accounts, create's new user accounts or disabled decommissioned accounts with information gathered from a CSV file 
and logs information to a log file in the working directory. 

If you run this script as a scheduled task, you need to specify the credentials as an encrypted file.
[Here's a blog on how to do that](https://blogs.technet.microsoft.com/robcost/2008/05/01/powershell-tip-storing-and-using-password-credentials/)


# Getting Started
Download the PowerShell script from [Azure DevOps Repo](https://dev.azure.com/mattchatt42/_git/Cape%20Union%20Mart#path=%2FUpdateFromSage.ps1&version=GBmaster)

#   System requirements to run updateFromSage.ps1:
1.	Windows 10 or Windows Server 2012/2016 as a member of the Domain.
2.  Active Directory PowerShell Module
3.  Windows RSAT Hotfix.(KB2693643)
    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
4.  Service Account Credentials with Write access to Active Directory.


# Test
*   Before running this script in Production Active Directory, test it in a Development environment!!
*   It is strongly suggested that the script is run on a dedicated Windows machine that is a member of the domain, but NOT on a domain controller.
*   Script tested on Windows 10.

# Run the script
EXAMPLE

   '.\UpdateFromSage.ps1' -CSVfilePath C:\Temp\SageUsers.csv -DisabledOU "OU=Disabled Users,DC=Contoso,DC=Com" -NewUserOU "OU=New Users,DC=Contoso,DC=Com" -ADServer "DC01"

Keywords: AD Update, CSV, NBConsult

# Email: support@nbconsult.co.za
