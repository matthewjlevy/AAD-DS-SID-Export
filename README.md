# Introduction 
ExportSIDfromAADDS.ps1
This script will Export to CSV a table of Users and their SID values from Azure AD Domain Services. 

If you run this script as a scheduled task, you need to specify the credentials as an encrypted file.
[Here's a blog on how to do that](https://blogs.technet.microsoft.com/robcost/2008/05/01/powershell-tip-storing-and-using-password-credentials/)


# Getting Started
Download the PowerShell script from [Github](https://dev.azure.com/mattchatt42/_git/Cape%20Union%20Mart#path=%2FExportSIDfromAADDS.ps1&version=GBmaster)

#   System requirements to run ExportSIDfromAADDS.ps1:
1.	Windows 10 or Windows Server 2012/2016 as a member of the Domain.
2.  Active Directory PowerShell Module
3.  Windows RSAT Hotfix.(KB2693643)
    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
4.  Read access to Azure Active Directory Domain Services.


# Test
*   Before running this script in Production Active Directory, test it in a Development environment!!
*   It is strongly suggested that the script is run on a dedicated Windows machine that is a member of the domain, but NOT on a domain controller.
*   Script tested on Windows 10.

# Run the script
EXAMPLE

   '.\ExportSIDfromAADDS.ps1' -SourceCSVFilePath C:\Temp\AIAUsers.csv -Domain contsoaadds.com -OutputCSV C:\Temp\AADDSSid.csv

Keywords: AD Export, CSV, NBConsult

# Email: support@nbconsult.co.za
