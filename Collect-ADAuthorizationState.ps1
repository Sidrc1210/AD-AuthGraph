<#
 .SYNOPSIS
 	Collects Active Directory authorization state for graph modeling

.DESCRIPTION
	Extracts directory-level authority relationships including:
	- Users, Groups, Computers
	- Group memberships (direct and nested)
	- Service Principal Names (SPNs)
	- Delegation configurations
	- ACL permissions on AD objects

	Output: JSON file containing nodes and edges for authorization graph

.PARAMETER OutputFile
	Path to output JSON file (default: ad_authorization_state.json)

.PARAMETER Domain
	Domain to query (default: current domain)

.PARAMETER IncludeBuiltIn
	Include built-in groups in analysis (default: $true)

.EXAMPLE
	.\Collect-ADAuthorizationState.ps1

.EXAMPLE
	.\Collect-ADAuthorizationState.ps1 -OutputFile "blues_state0_clean.json"

.NOTES
	Author: [Siddharth Ray Chaudhuri]
	Date: 2026-02-10
	Purpose: Authorization Graph Modeling Project
	Requirements: ActiveDirectory PowerShell module, Domain Admin or read permissions
#>


[CmdletBinding()]
param(
     [Parameter(Mandatory=$false)]
     [string]$OutputFile = "ad_authorization_state.json",

     [Parameter(Mandatory=$false)]
     [string]$Domain = $env:USERDNSDOMAIN,

     [Parameter(Mandatory=$false)]
     [bool]$IncludeBuiltIn = $true

     )

$ErrorActionPreference = "Stop"

# Import required module
try { 
     Import-Module ActiveDirectory -ErrorAction Stop
     Write-Host "[+] ActiveDirectory module loaded" -ForegroundColor Green
} catch {
     Write-Host "[-] Failed to load ActiveDirectory module: $_" -ForegroundColor Red
     exit 1
}

# Initialize caches for performance 
$script:SIDCache = @{}
$script:ExtendedRightCache = @{}
$script:ConfigNC = (Get-ADRootDSE).configurationNamingContext

# Initialize output structure
$authorizationState = @{
     metadata = @{
          collection_date = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
          domain = $Domain
          collector_version = "1.1" # Updated for schema-aware resolution
          description = "Active Directory authorization state snapshot"
      }
      users = @()
      groups = @()
      computers = @()
      group_memberships = @()
      spns = @()
      delegation = @()
      acl_permissions = @()
      statistics = @{
           user_count = 0
           group_count = 0
           computer_count = 0
           membership_count = 0
           spn_count = 0
           delegation_count = 0
           acl_count = 0
      }
}

Write-Host "`n=== Active Directory Authorization State Collection ==="  -ForegroundColor Cyan
Write-Host "Domain: $Domain" -ForegroundColor Cyan
Write-Host "Output: $OutputFile" -ForegroundColor Cyan
Write-Host ""


# region Helper Functions

 function Get-ObjectSID {
 	param($ADObject)
 	if ($ADObject.SID) {
 	    return $ADObject.SID.Value
        } elseif ($ADObject.ObjectSID) {
 	    return $ADObject.ObjectSID.Value
        }
         return $null
  }

 function Resolve-SIDToIdentity {
 	param([string]$SID)  

        # Check Cache first
        if ($script:SIDCache.ContainsKey($SID)) {
               return $script:SIDCache[$SID]
 	} 
        
        try { 
            $identity = Get-ADObject -Filter { ObjectSID -eq $SID } -Properties SamAccountName, ObjectClass -ErrorAction Stop
            if ($identity) {     
		$result = "$($identity.ObjectClass):$($identity.SamAccountName)"
                $script:SIDCache[$SID] = $result
                return $result
             }
         } catch {
              # SID might be a well-known or external
              $script:SIDCache[$SID] = "Unknown:$SID"
              return "Unknown:$SID"
         }

         return "Unknown:$SID"
    }

 function Resolve-ExtendedRight {
    param([Guid]$Guid)

    if (-not $Guid -or $Guid -eq [Guid]::Empty) {
        return $null
    }

    $guidString = $Guid.ToString()
    if ($script:ExtendedRightCache.ContainsKey($guidString)) {
        return $script:ExtendedRightCache[$guidString]
    }

    try {
        $result = Get-ADObject -SearchBase "CN=Extended-Rights,$($script:ConfigNC)" `
                              -LDAPFilter "(rightsGuid=$guidString)" `
                              -Properties displayName -ErrorAction SilentlyContinue
        
        $name = if ($result) { $result.displayName } else { "Unknown-Right:$guidString" }
        $script:ExtendedRightCache[$guidString] = $name
        return $name
    }
    catch {
        return $null
    }
}

    
    function Get-NestedGroupMembers {
           param(
                [string]$GroupDN,
                [hashtable]$Visited = @{}      
           )

           # Prevent infinite recursion
           if ($Visited.ContainsKey($GroupDN)) {
               return @()
           }
           $Visited[$GroupDN] = $true

           $allMembers = @()

           try { 
               $group = Get-ADGroup -Identity $GroupDN -Properties Members -ErrorAction Stop   
 
           foreach ($memberDN in $group.Members) {
               try {
                   $member = Get-ADObject -Identity $memberDN -Properties ObjectClass, SamAccountName -ErrorAction Stop
     
                   # Add this member
                   $allMembers += @{
                       dn = $member.DistinguishedName 
                       sam = $member.SamAccountName
                       type = $member.ObjectClass
                       direct = $true
                   }

                   # If member is a group, recurse
                   if ($member.ObjectClass -eq "group") {
                       $nestedMembers = Get-NestedGroupMembers -GroupDN $member.DistinguishedName -Visited $Visited
                       	foreach ($nested in $nestedMembers) {
                              $nested.direct = $false
                              $allMembers += $nested
                        }
                    }
          } catch {
                Write-Warning "Failed to resolve member: $memberDN"
          }
      }
   } catch {
       Write-Warning "failed to get members of group: $GroupDN"
   }
      
     return $allMembers
}

# endregion


#region Collect Users

Write-Host "[*] Collecting users..." -ForegroundColor Yellow

try {
    $users = Get-ADUser -Filter * -Properties `
          SamAccountName, `
          DistinguishedName, `
          ObjectSID, `
          MemberOf, `
          ServicePrincipalNames, `
          Enabled, `
          Description, `
          TrustedForDelegation, `
          TrustedToAuthForDelegation, `
          'msDS-AllowedToDelegateTo'

      foreach ($user in $users) {
           $userObj = @{
                sam_account_name = $user.SamAccountName
                distinguished_name = $user.DistinguishedName
                sid = Get-ObjectSID -ADObject $user
                enabled = $user.Enabled
                description = $user.Description
                spn_count = ($user.ServicePrincipalNames | Measure-Object).Count
                member_of_count = ($user.MemberOf | Measure-Object).Count
                has_delegation = $user.TrustedForDelegation -or $user.TrustedToAuthForDelegation
             }
             
             $authorizationState.users += $userObj
             $authorizationState.statistics.user_count++
         }

         Write-Host "    [+] Collected $($authorizationState.statistics.user_count) users" -ForegroundColor Green
      } catch {
          Write-Host "   [-] Failed to collect users: $_" -ForegroundColor Red
      }

#endregion

#region Collect Groups

Write-Host "[*]  Collecting groups..." -ForegroundColor Yellow

try {
    $groupFilter = if ($IncludeBuiltIn) { "*" } else {
          # Exclude built-in groups (customize as needed)
          { (DistinguishedName -notlike "*CN=Builtin,*") -and (DistinguishedName -notlike "*CN=Users,*") }
    }

    $groups = Get-ADGroup -Filter $groupFilter -Properties `
         SamAccountName, `
         DistinguishedName, `
         ObjectSID, `
         Members, `
         MemberOf, `
         Description, `
         GroupCategory, `
         GroupScope

    foreach ($group in $groups) {
          $groupObj = @{
               sam_account_name = $group.SamAccountName
               distinguished_name = $group.DistinguishedName
               sid = Get-ObjectSID -ADObject $group  
               description = $group.Description
               group_category = $group.GroupCategory.ToString()
               group_scope = $group.GroupScope.ToString()
               member_count = ($group.Members | Measure-Object).Count
               member_of_count = ($group.MemberOf | Measure-Object).Count
           }
  
           $authorizationState.groups += $groupObj
           $authorizationState.statistics.group_count++
       }

       Write-Host "    [+] Collected $($authorizationState.statistics.group_count) groups" -ForegroundColor Green
   } catch {
       Write-Host "    [-] Failed to collect groups: $_" -ForegroundColor Red

  }


#endregion

#region Collect Computers

Write-Host "[*]  Collecting computers..." -ForegroundColor Yellow

try {
    $computers = Get-ADComputer -Filter * -Properties `
          SamAccountName, `
          DistinguishedName, `
          ObjectSID, `
          ServicePrincipalNames, `
          OperatingSystem, `
          Enabled, `
          TrustedForDelegation, `
          TrustedToAuthForDelegation, `
          'msDS-AllowedToDelegateTo'

     foreach ($computer in $computers) {
          $computerObj = @{
                sam_account_name = $computer.SamAccountName
                distinguished_name = $computer.DistinguishedName
                sid = Get-ObjectSID -ADObject $computer
                operating_system = $computer.OperatingSystem
                enabled = $computer.Enabled
                spn_count = ($computer.ServicePrincipalNames | Measure-Object).Count
                trusted_for_delegation = $computer.TrustedForDelegation
                constrained_delegation = $computer.TrustedToAuthForDelegation
           }

           $authorizationState.computers += $computerObj
           $authorizationState.statistics.computer_count++

       }

             Write-Host "    [+] Collected $($authorizationState.statistics.computer_count) computers" -ForegroundColor Green
       } catch {
             Write-Host "    [-] Failed to collect computers: $_" -ForegroundColor Red
       }

#endregion

#region Collect Group Memberships

Write-Host "[*] Collecting group memberships (including nested)..." -ForegroundColor Yellow


try {
    foreach ($group in $groups) {
          $members = Get-NestedGroupMembers -GroupDN $group.DistinguishedName

          foreach ($member in $members) {
                $membershipObj = @{
                       member_sam = $member.sam
                       member_type = $member.type
                       member_dn = $member.dn
                       group_sam = $group.SamAccountName     
                       group_dn = $group.DistinguishedName
                       direct_membership = $member.direct
                   }

                   $authorizationState.group_memberships += $membershipObj
                   $authorizationState.statistics.membership_count++
                }
             }

              Write-Host "     [+] Collected $($authorizationState.statistics.membership_count) group memberships" -ForegroundColor Green
          } catch {
              Write-Host "    [-] Failed to collect memberships: $_" -ForegroundColor Red
          }

       

#endregion


#region Collect Service Principal Names (SPNs)

Write-Host "[*] Collecting Service Principal Names (SPNs)..." -ForegroundColor Yellow


try {
     # Collect SPNs from users
     foreach ($user in $users) {
  	  if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                foreach ($spn in $user.ServicePrincipalNames) {
                      $spnObj = @{
                           identity_sam =$user.SamAccountName
                           identity_type = "user"
                           identity_dn = $user.DistinguishedName
                           spn = $spn
                           enabled = $user.Enabled
                      }

                       $authorizationState.spns += $spnObj
                       $authorizationState.statistics.spn_count++
                      }
                 }
          }



          #Collect SPNs from computers
          foreach ($computer in $computers) {
               if ($computer.ServicePrincipalNames -and $computer.ServicePrincipalNames.Count -gt 0) {

                   foreach ($spn in $computer.ServicePrincipalNames) {
                        # Filter out default computer SPNs (optional - keeps data cleaner)
                        if ($spn -notmatch "^(HOST|TERMSRV|RestrictedKrbHost)/"){ 
                            $spnObj = @{
                                  identity_sam = $computer.SamAccountName
                                  identity_type = "computer"
                                  identity_dn = $computer.DistinguishedName
                                  spn = $spn
                                  enabled = $computer.Enabled
                              }

                               $authorizationState.spns += $spnObj
                               $authorizationState.statistics.spn_count++
                           }
                       }

                   }
              }
         
               Write-Host "      [+] Collected $($authorizationState.statistics.spn_count) SPNs" -ForegroundColor Green

        } catch {
                Write-Host "     [-] failed to collect SPNs: $_ " -ForegroundColor Red
        }

#endregion


#region Collect Delegation Settings

Write-Host "[*] Collecting delegation configurations..." -ForegroundColor Yellow

try {
    # check users for delegation
    foreach ($user in $users) {
	if ($user.TrustedForDelegation -or $user.TrustedToAuthForDelegation -or $user.'msDS-AllowedToDelegateTo') {
             $delegationType = if ($user.TrustedForDelegation) { 
                   "unconstrained"
             } elseif ($user.TrustedToAuthForDelegation) {
                   "constrained_with_protocol_transition"
             } else {
                 "constrained"
             } 

             $delegationObj = @{
                     identity_sam = $user.SamAccountName
                     identity_type = "user"
                     identity_dn = $user.DistinguishedName
                     delegation_type = $delegationType
                     allowed_targets = $user.'msDS-AllowedToDelegateTo'
                     enabled = $user.Enabled
              }

               $authorizationState.delegation += $delegationObj
               $authorizationState.statistics.delegation_count++
            }

          }

   # Check computers for delegation
   foreach ($computer in $computers) {
         if ($computer.TrustedForDelegation -or $computer.TrustedToAuthForDelegation -or $computer.'msDS-AllowedToDelegateTo') {
               $delegationType = if ($computer.TrustedForDelegation) {
                     "unconstrained"
               } elseif ($computer.TrustedToAuthForDelegation) {
                     "constrained_with_protocol_transition"
               } else {
                     "constrained"
               }
 
               $delegationObj = @{
                         identity_sam = $computer.SamAccountName
                         identity_type = "computer"
                         identity_dn = $computer.DistinguishedName
                         delegation_type = $delegationType
                         allowed_targets = $computer.'msDS-AllowedToDelegateTo'
                         enabled = $computer.Enabled
                    }

                     $authorizationState.delegation += $delegationObj
                     $authorizationState.statistics.delegation_count++
                }
            }

             Write-Host "    [+] Collected $($authorizationState.statistics.delegation_count) delegation configurations" -ForegroundColor Green

} catch {
     Write-Host "    [-] failed to collect delegation settings: $_" -ForegroundColor Red

}


#endregion

#region Collect ACL Permissions

Write-Host "[*] Collecting ACL permissions (this may take a while)..." -ForegroundColor Yellow

try {
    # Define interesting rights to collect 
    $interestingRights = @(
          "GenericAll"
          "GenericWrite"
          "WriteProperty"
          "WriteDacl"
          "WriteOwner"
          "ResetPassword"
          "ExtendedRight"
      )

       # Collect ACLs on users (high-value targets)
       $usercount = 0
       foreach ($user in $users) {
           try {
               $acl = Get-ACL -Path "AD:$($user.DistinguishedName)" -ErrorAction Stop
               
               foreach ($access in $acl.Access) {
               # Skip inherited permissions (focus on explicit misconfigurations)
               if ($access.IsInherited) {continue}

               # Check if permission is interesting
               $rightsString = $access.ActiveDirectoryRights.ToString()
               $isInteresting = $false

               foreach ($right in $interestingRights) {
                    if ($rightsString -match $right) {
                        $isInteresting = $true
                        break
                      }
                  }

                   if ($isInteresting) {
                         # Resolve trustee SID to identity
                         $trusteeSID = $access.IdentityReference.Value
                         if ($trusteeSID -match "^S-1-5-21-") {
                            $trusteeIdentity = Resolve-SIDToIdentity -SID $trusteeSID
                         } else {
                             $trusteeIdentity = $trusteeSID
                         }
                         
                         $objectTypeGuid = $access.ObjectType
                         $extendedRightName = $null

                         # Bitwise check for ExtendedRight and resolve against schema
                         if ($access.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                            if ($objectTypeGuid -ne [Guid]::Empty) {
                                $extendedRightName = Resolve-ExtendedRight -Guid $objectTypeGuid
                            }
                         }

                         if ($objectTypeGuid -eq [Guid]::Empty) {
                            $objectTypeGuid = $null
                         }

                         $aclObj = @{
                             target_sam = $user.SamAccountName
                             target_type = "user"
                              target_dn = $user.DistinguishedName
                              trustee_identity = $trusteeIdentity
                              trustee_sid = $trusteeSID
                              permission = $rightsString
                              object_type_guid = $objectTypeGuid
                              extended_right_name = $extendedRightName
                              access_control_type = $access.AccessControlType.ToString()
                              is_inherited = $access.IsInherited 
                              inheritance_flags = $access.InheritanceFlags.ToString()
                         }
       
                         $authorizationState.acl_permissions += $aclObj
                         $authorizationState.statistics.acl_count++
                     }
                  }
                  
                   $userCount++
                   if ($userCount % 10 -eq 0) {
                       Write-Host "    [*] Processed ACLs for $userCount users..." -ForegroundColor Gray            
                    }
                } catch {
                     Write-Warning "failed to get ACL for user: $($user.SamAccountName)"
                }
             }
    
             # Collect ACLs on groups (especially privileged groups)
             $groupCount = 0
             foreach ($group in $groups) {
                   try { 
                        $acl = Get-ACL -Path "AD:$($group.DistinguishedName)" -ErrorAction Stop
                        foreach ($access in $acl.Access) {
                             if ($access.IsInherited) { continue }

                             $rightsString = $access.ActiveDirectoryRights.ToString()
                             $isInteresting = $false

                             foreach ($right in $interestingRights) {
                                  if ($rightsString -match $right) {
                                      $isInteresting = $true
                                      break
                                  }
                               }
                    
                                if ($isInteresting) {
                                    $trusteeSID = $access.IdentityReference.Value
                                    if ($trusteeSID -match "^S-1-5-21-") {
                                        $trusteeIdentity = Resolve-SIDToIdentity -SID $trusteeSID 
                                     } else {
                                         $trusteeIdentity = $trusteeSID
                                     }
                                     
                                     $objectTypeGuid = $access.ObjectType
                                     $extendedRightName = $null

                                     # Bitwise check for ExtendedRight and resolve against schema
                                     if ($access.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                                        if ($objectTypeGuid -ne [Guid]::Empty) {
                                            $extendedRightName = Resolve-ExtendedRight -Guid $objectTypeGuid
                                        }
                                     }

                                     if ($objectTypeGuid -eq [Guid]::Empty) {
                                        $objectTypeGuid = $null 
                                     }

                                     $aclObj = @{
                                         target_sam = $group.SamAccountName
                                         target_type = "group"
                                         target_dn = $group.DistinguishedName
                                         trustee_identity = $trusteeIdentity
                                         trustee_sid = $trusteeSID
                                         permission = $rightsString
                                         object_type_guid = $objectTypeGuid 
                                         extended_right_name = $extendedRightName
                                         access_control_type = $access.AccessControlType.ToString()
                                         is_inherited = $access.IsInherited
                                         inheritance_flags = $access.InheritanceFlags.ToString()
                                      }
     
                                      $authorizationState.acl_permissions += $aclObj
                                      $authorizationState.statistics.acl_count++

                                   }
                               }
                             
                                $groupCount++
                                if ($groupCount % 10 -eq 0) {
                                    Write-Host "    [*] Processed ACLs for $groupCount groups..." -ForegroundColor Gray
                                 }
                              } catch {
                                   Write-Warning "failed to get ACL for group: $($group.SamAccountName)"
                             }
                          }
           
                          Write-Host "   [+] Collected $($authorizationState.statistics.acl_count) ACL permissions" -ForegroundColor Green
                      } catch { 
                           Write-Host "   [-] Failed to collect ACL permissions: $_" -ForegroundColor Red
                     }

#endregion

#region Export to JSON

Write-Host "`n[*] Exporting to JSON..." -ForegroundColor Yellow

try {
    $json = $authorizationState | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputFile -Encoding UTF8

    $fileSize = (Get-Item $OutputFile).Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)

    Write-Host "    [+] Export successful: $OutputFile ($fileSizeKB KB)" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to export JSON: $_" -ForegroundColor Red
    exit 1
}

#endregion

Write-Host "`n=== Collection Summary ===" -ForegroundColor Cyan
Write-Host "Users:                 $($authorizationState.statistics.user_count)" -ForegroundColor White
Write-Host "Groups:                $($authorizationState.statistics.group_count)" -ForegroundColor White
Write-Host "Computers:             $($authorizationState.statistics.computer_count)" -ForegroundColor White
Write-Host "Group Memberships:     $($authorizationState.statistics.membership_count)" -ForegroundColor White
Write-Host "SPNs:                  $($authorizationState.statistics.spn_count)" -ForegroundColor White 
Write-Host "Delegations:           $($authorizationState.statistics.delegation_count)" -ForegroundColor White
Write-Host "ACL Permissions:        $($authorizationState.statistics.acl_count)" -ForegroundColor White
Write-Host "`n[+] Collection complete!" -ForegroundColor Green
Write-Host "Next step: python main.py --state $OutputFile`n" -ForegroundColor Cyan