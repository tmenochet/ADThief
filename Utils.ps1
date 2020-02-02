function Add-DSAccountCustomViews {
    param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

	[XML]$viewSecretsDump = @'
<View>
  <Name>SecretsDump</Name>
  <!-- Format: <domain>\<username>:<uid>:<LM-hash>:<NT-hash>:<comment>:<homedir>: -->
  <ViewSelectedBy>
    <TypeName>DSInternals.Common.Data.DSAccount</TypeName>
  </ViewSelectedBy>
  <CustomControl>
    <CustomEntries>
      <CustomEntry>
        <CustomItem>
          <ExpressionBinding>
            <PropertyName>DistinguishedName</PropertyName>
            <CustomControlName>Domain</CustomControlName>
          </ExpressionBinding>
          <ExpressionBinding>
            <ScriptBlock>
            if ($PSItem.UserPrincipalName -eq $null){
                $pattern = '(?i)DC=[^,]+\b'
                ([RegEx]::Matches($PSItem.DistinguishedName, $pattern) | ForEach-Object { $_.Value }) -replace 'DC=' -join '.'
            }
            else {
                $($PSItem.UserPrincipalName).Split('@')[1]
            }
            </ScriptBlock>
          </ExpressionBinding>
          <Text>\</Text>
          <ExpressionBinding>
            <PropertyName>SamAccountName</PropertyName>
          </ExpressionBinding>
          <Text>:</Text>
          <ExpressionBinding>
            <PropertyName>Sid</PropertyName>
            <CustomControlName>Rid</CustomControlName>
          </ExpressionBinding>
          <Text>:</Text>
          <ExpressionBinding>
            <PropertyName>LMHash</PropertyName>
            <CustomControlName>Hash</CustomControlName>
          </ExpressionBinding>
          <ExpressionBinding>
            <ScriptBlock>if($PSItem.LMHash -eq $null) { 'aad3b435b51404eeaad3b435b51404ee' }</ScriptBlock>
          </ExpressionBinding>
          <Text>:</Text>
          <ExpressionBinding>
            <PropertyName>NTHash</PropertyName>
            <CustomControlName>Hash</CustomControlName>
          </ExpressionBinding>
          <ExpressionBinding>
            <ScriptBlock>if($PSItem.NTHash -eq $null) { '31d6cfe0d16ae931b73c59d7e0c089c0' }</ScriptBlock>
          </ExpressionBinding>
          <Text>:::</Text>
        </CustomItem>
      </CustomEntry>
    </CustomEntries>
  </CustomControl>
</View>
'@

	[XML]$viewSecretsDumpHistory = @'
<View>
  <Name>SecretsDumpHistory</Name>
  <!-- Format: <domain>\<username>:<uid>:<LM-hash>:<NT-hash>:<comment>:<homedir>: -->
  <ViewSelectedBy>
    <TypeName>DSInternals.Common.Data.DSAccount</TypeName>
  </ViewSelectedBy>
  <CustomControl>
    <CustomEntries>
      <CustomEntry>
        <CustomItem>
          <ExpressionBinding>
            <ScriptBlock>
              $records = [System.Collections.ArrayList]@()
              if ($PSItem.UserPrincipalName -eq $null){
                $pattern = '(?i)DC=[^,]+\b'
                $domain = ([RegEx]::Matches($PSItem.DistinguishedName, $pattern) | ForEach-Object { $_.Value }) -replace 'DC=' -join '.'
              }
              else {
                $domain = $($PSItem.UserPrincipalName).Split('@')[1]
              }
              
              $samAccountName = $PSItem.SamAccountName
              $rid = [DSInternals.Common.SecurityIdentifierExtensions]::GetRid($PSItem.Sid)
              if($PSItem.LMHash -eq $null -Or (ConvertTo-Hex $PSItem.LMHash) -eq 'aad3b435b51404eeaad3b435b51404ee') { $lmHash = 'aad3b435b51404eeaad3b435b51404ee' }
              else { $lmHash = ConvertTo-Hex $PSItem.LMHash }
              if($PSItem.NTHash -eq $null) { $ntHash = '31d6cfe0d16ae931b73c59d7e0c089c0' }
              else { $ntHash = ConvertTo-Hex $PSItem.NTHash }
              
              $record = '{0}\{1}:{2}:{3}:{4}:::' -f $domain, $SamAccountName, $rid, $lmHash, $ntHash
              $position = $records.Add($record)
              
              for($i=1; $i -lt $PSItem.NTHashHistory.Count; $i++)
              {
                if($PSItem.LMHashHistory[$i] -eq $null -Or (ConvertTo-Hex $PSItem.LMHashHistory[$i]) -eq 'aad3b435b51404eeaad3b435b51404ee') { $lmHash = 'aad3b435b51404eeaad3b435b51404ee' }
                else { $lmHash = ConvertTo-Hex $PSItem.LMHashHistory[$i] }
                if($PSItem.NTHashHistory[$i] -eq $null) { $ntHash = '31d6cfe0d16ae931b73c59d7e0c089c0' }
                else { $ntHash = ConvertTo-Hex $PSItem.NTHashHistory[$i] }
                
                $record = '{0}\{1}_history{2}:{3}:{4}:{5}:::' -f $domain, $SamAccountName, ($i-1), $rid, $lmHash, $ntHash
                $position = $records.Add($record)
              }
              $records -join [Environment]::NewLine
            </ScriptBlock>
            <EnumerateCollection/>
          </ExpressionBinding>
        </CustomItem>
      </CustomEntry>
    </CustomEntries>
  </CustomControl>
</View>
'@

	if(-Not(Get-Module -Name DSInternals -ListAvailable)) {
		Write-Warning "DSInternals PowerShell module is not installed."
		Write-Warning "Please run command 'Install-Module -Name DSInternals' first"
		Exit 1
	}
	if (-not $Path) {
		$modulePath = (Get-Module -Name DSInternals -ListAvailable).Path
		$Path = "$modulePath\..\Views\DSInternals.DSAccount.ExportViews.format.ps1xml"
	}
	$Path = Resolve-Path -Path $Path
	$doc = New-Object System.Xml.XmlDocument
	$doc.Load($Path)
	$views = $doc.DocumentElement.ViewDefinitions.View
	if (-not ($views | Select -ExpandProperty Name).Contains('SecretsDump')) {
		$doc.DocumentElement.ViewDefinitions.AppendChild($doc.ImportNode($viewSecretsDump.View, $true)) | Out-Null
	}
	if (-not ($views | Select -ExpandProperty Name).Contains('SecretsDumpHistory')) {
		$doc.DocumentElement.ViewDefinitions.AppendChild($doc.ImportNode($viewSecretsDumpHistory.View, $true)) | Out-Null
	}
	try {
		$doc.Save($Path)
		Write-Host "File $Path updated"
	}
	catch {
		Write-Warning "Error setting path $Path : $_"
	}
}