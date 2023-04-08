<#
Delegates administrative functions to the DNS Servers and Zones without using DNSAdmins
Each forward and reverse zone is delegated by an individual AD group that also provides READ access to the DNS servers
Top level access to fully manage the DNS servers is via AT_DNS_MicrosoftDNS_Manage

Requires: 
AD powershell modules
Update the OU DN to reflect where AD Groups will be created
#>

Import-Module activedirectory    
Set-Location AD:

#Get the DN for the Domain
$rootDSE = (Get-ADRootDSE).rootDomainNamingContext

#Get all Forward and Reverse DNS Zones
$gtDnsZones = Get-ChildItem "CN=MicrosoftDNS,DC=DomainDnsZones,$($rootDSE)" -Exclude RootDNSServers

#Get the DN for the DNS Servers - Top Level DNS Configuration
$gtRootDns = Get-Item "CN=MicrosoftDNS,CN=System,$($rootDSE)" 
$rootDNSName = $gtRootDns.Name

#Get DN for Forward and Reverse level - Required for creating new zones
$gtRootDNSZone = Get-Item "CN=MicrosoftDNS,DC=DomainDnsZones,$($rootDSE)"
$rootDNSZoneName = $gtRootDNSZone.name

#RootHints DN
$gtRootDNSHint = "DC=RootDNSServers,CN=MicrosoftDNS,DC=DomainDnsZones,$($rootDSE)"

#UPDATE - update the DN to reflect where AD Groups will be created
$ouDelegation = "OU=Delegation,OU=Resources,$($rootDSE)"

#Loop through creating AD Groups to delegate Full Control of each Forward and Reverse DNS Zone and Read to the DNS Server Zone
foreach ($zone in $gtDnsZones)
{   
    #Get the DN and Name for each Zone     
    $zoneName = $zone.name
    $zoneDN = $zone.DistinguishedName
    
    #Create a AD Group based on the Zone Name
    $adGpName = "AT_DNSZone_$($zoneName)_Manage"
    New-ADGroup -Name $adGpName -GroupScope Global -Path $ouDelegation

    #Get the AD Groups Sid
    $getGp = Get-ADGroup -Identity $adGpName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID

    #Full Control of each zone    
    $dnsACL = Get-Acl -Path $zoneDN
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsACL.AddAccessRule($ACE)
    Set-Acl -Path $zoneDN -AclObject $dnsACL

    #RootServer DN and Set READ for the AD Groups - Allows conection to the DNS Server
    $dnsRtACL = Get-Acl -Path $gtRootDnsZones

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsRtACL.AddAccessRule($ACE)
    Set-Acl -Path $gtRootDnsZones -AclObject $dnsRtACL
}

    #SERVER Manage
    #Create AD Group for delegting FULL control of the DNS Servers
    $adGpName = "AT_DNSServer_$($rootDNSName)_Manage"
    New-ADGroup -Name $adGpName -GroupScope Global -Path $ouDelegation

    #Get the AD Groups Sid
    $getGp = Get-ADGroup -Identity $adGpName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID

    #RootServer DN and Set FULL Control
    $dnsRtACL = Get-Acl -Path $gtRootDns
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsRtACL.AddAccessRule($ACE)
    Set-Acl -Path $gtRootDns -AclObject $dnsRtACL

    #RootHint DN and Set FULL Control
    $dnsRtACL = Get-Acl -Path $gtRootDNSHint
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsRtACL.AddAccessRule($ACE)
    Set-Acl -Path $gtRootDNSHint -AclObject $dnsRtACL



    #ZONE Manage
    #Create AD Group for delegting permissions to create Zones
    $adGpName = "AT_DNSZone_$($rootDNSZoneName)_Manage"
    New-ADGroup -Name $adGpName -GroupScope Global -Path $ouDelegation

    #Get the AD Groups Sid
    $getGp = Get-ADGroup -Identity $adGpName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID

    #RootServer DN and Set FULL Control
    $dnsRtACL = Get-Acl -Path $gtRootDNSZone
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsRtACL.AddAccessRule($ACE)
    Set-Acl -Path $gtRootDNSZone -AclObject $dnsRtACL

    #RootServer DN and Set READ for the AD Groups - Allows conection to the DNS Server
    $dnsRtACL = Get-Acl -Path $gtRootDnsZones
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $GroupSID,$ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
    $dnsRtACL.AddAccessRule($ACE)
    Set-Acl -Path $gtRootDnsZones -AclObject $dnsRtACL


