#Script to apply the acl permissions on the custome OUs

Import-Module ActiveDirectory

function Add-ADPermission {
      param (
            [string]$TargetGroup,
            [string]$User,
            [string]$Right
      )

      $group = Get-ADGroup $TargetGroup
      $entry = [ADSI]"LDAP://$($group.DistinguishedName)"
      $acl = $entry.psbase.ObjectSecurity

      $nt = New-Object System.Security.Principal.NTAccount($User)
      $accessRight = [System.DirectoryServices.ActiveDirectoryRights]::$Right

      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            ($nt, $accessRight, "Allow")

      $acl.RemoveAccessRule($rule)
      $acl.AddAccessRule($rule)      
            
      $entry.psbase.ObjectSecurity = $acl
      $entry.psbase.CommitChanges()

}        

Add-ADPermission "Finance" "BLUES\vkohli" "GenericAll"
Add-ADPermission "Director" "BLUES\vkohli" "WriteDACL"
Add-ADPermission "Administration" "BLUES\vkohli" "ReadProperty"
Add-ADPermission "Sales" "BLUES\vkohli" "WriteDACL"
Add-ADPermission "Director" "BLUES\jbumrah" "WriteDACL"
Add-ADPermission "Administration" "BLUES\jbumrah" "ReadProperty"
Add-ADPermission "Sales" "BLUES\jbumrah" "WriteDACL"
Add-ADPermission "HR" "BLUES\rsharma" "GenericAll"
Add-ADPermission "Administration" "BLUES\rsharma" "ReadProperty"
Add-ADPermission "IT" "BLUES\rashwin" "GenericWrite"
Add-ADPermission "Finance" "BLUES\rashwin" "WriteProperty"
Add-ADPermission "IT" "BLUES\arahane" "WriteProperty"
Add-ADPermission "IT" "BLUES\rjadeja" "WriteProperty"
Add-ADPermission "Finance" "BLUES\arahane" "WriteProperty"
Add-ADPermission "Sales" "BLUES\rpant" "WriteProperty"
Add-ADPermission "Helpdesk" "BLUES\mdsiraj" "WriteProperty"




