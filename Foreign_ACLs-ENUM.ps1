$Domain = "inlanefreight.ad"
$DomainSid = Get-DomainSid $Domain

Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * | ? { 
	($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and `
	($_.AceType -match 'AccessAllowed') -and `
	($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and `
	($_.SecurityIdentifier -notmatch $DomainSid)
} 
