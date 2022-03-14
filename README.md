# Responding to sophisticated attacks on Microsoft 365 and Azure AD 

Working notes on responding to sophisticated attacks on Microsoft 365 and Azure AD (include those carried out by the threat actor [Nobelium](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)). 

## Background on Nobelium 

Nobelium has been one of the most prolific and technically-sophisticated threat actors observed over the last couple of years. 

Nobelium distinguished itself from other threat actors, in its skill and adeptness at compromising organisations' Azure AD and Microsoft 365 cloud environments. Nobelium has been able to do this by combining both well known techniques (e.g. password spraying) and novel techniques into innovative attack paths that allow them to compromise accounts and gain long-term and stealthy access to data stored in cloud services. This is likely reflective of a significant investment Nobelium has made in researching offensive techniques against Microsoft cloud environments.

We will almost certainly see the techniques and tradecraft Nobelium has developed trickling down to other threat actors over the next couple of years, after Nobelium has demonstrated their effectiveness at gaining stealthy access to data. Nobelium has also demonstrated how these techniques can be used to evade traditional endpoint and network security monitoring, making them especially effective at targeting  organisations with more mature cyber security controls that can reliably detect common attacker techniques on endpoints. 

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

More good resources to learn more about Azure incident response, Microsoft Sentinel and KQL:
* [Azure AD incident response playbooks](https://docs.microsoft.com/en-us/security/compass/incident-response-playbooks)
* [Using KQL in incident response](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/leveraging-the-power-of-kql-in-incident-response/ba-p/3044795)
* [@reprise_99](https://twitter.com/reprise_99)'s [blog](https://learnsentinel.blog/) and [github repo of Sentinel queries](https://github.com/reprise99/Sentinel-Queries)
* [Azure Cloud & AI Domain blog](https://azurecloudai.blog/)

Details on Azure AD offensive techniques and how to simulate these in a lab is covered [here](https://github.com/WillOram/AzureAD-incident-response/blob/main/README-OFFENSIVETECHNIQUES). 

## Mobilise the incident response team and secure their communications

-   **Agree response priorities and objectives** to guide decision making during the course of the response.

-   **Secure the response team’s communications** to ensure that the attacker is not able to intercept communications (an attacker could have ongoing access to emails if they have compromised the accounts of members of the response team, privileged accounts, or applications and service principals with sufficient permissions).

-   **Establish response programme governance and workstreams** to ensure that response activities are effectively coordinated.

-   **Manage the response** by establishing a regular cadence of meetings, tracking progress against the objectives, and managing risks and issues.

## Understand how users are authenticated and how Azure AD and Microsoft 365 are configured

-   **Map out the authentication flows for how users are authenticated**, including what trusted domains are configured, what authentication methods these domains use, and if federated, pass-the-hash, or pass-through-authentication is configured.

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

-   **Understand how Azure AD and Office 365 and secured**, including how logs are monitored for security alerts, what security controls / features are configured (e.g. Azure Privileged Identity Management) and how privilege groups are reviewed.

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

-   **Disable known compromised accounts, revoke the account's Azure AD refresh tokens and disable registered devices** ([see this Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-revoke-access) on the different types of authentication tokens and how to revoke all access for a user)

-   **Block logins for known bad IP addresses**, with Conditional Access rules 

-   **Remove delegated administrator permissions** from partner relationships (requires an account with Global Admin permissions)

-   **Create break-glass Global Admin accounts, monitor their usage and securely store the passwords**

-   **Restrict global administrator permissions** to members of the response team

-   **Review MFA configuration and validate self-service password reset contact information for privileged accounts**

-   **Rotate credentials for Service Principals and Applications and revoke refresh tokens**

-   **Reset passwords of all privileged accounts, revoke Azure AD refresh tokens and audit registered devices** 

-   **Configure number matching in multifactor authentication (MFA) notifications**

-   **Review guest / third-party accounts and disable accounts where possible**

## Perform a more comprehensive review to identify any persistent access the attacker has gained to accounts systems or data 

The configuration of Azure AD and Microsoft 365, as well as avaliable logs, should be reviewed for suspicious activity and malicious configuration changes, to identify any persistent access the attacker has gained to accounts, systems or data.

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

-   **Review Audit AD Audit logs to identify any malicious changes to the Azure AD tenant** for example adding [new or modifying existing federation settings](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml), or adding new [partner relationships](https://o365blog.com/post/partners/).

-   **Review Azure AD Signin logs to identify suspicious signins by third-party partner accounts using delegated administrator privileges**.  
 
### Hunt for Golden SAML attacks 

-   **Review Azure AD Sign-in logs for evidence of forged SAML tokens being used to authenticate to the tenant**, after the attacker has been able to compromise the organisation's ADFS token-signing certificate. 

-   **Review risk events and detections associated with privileged account logins** to identify any compromised accounts. 

### Hunt for the compromise of privileged accounts 

-   **Review accounts in privileged Azure AD and Exchange roles to identify any accounts added to privileged roles by the attacker**, including whether guest accounts and accounts used by third-parties have been added to privileged roles.

-   **Review Azure AD Sign-in logs to identify:** 
     -   **Suspicious logins**, for example for anomalous logins by country, impossible travel logins and logins from cloud services VPNs/VPSs/Azure/AWS/GCP (Note attackers have been seen using [residential IP proxy services or newly provisioned geo located infrastructure](https://www.mandiant.com/resources/russian-targeting-gov-business), to evade MFA and obfuscate logging (e.g. a geographically co-located azure instance))
     -   **Password spraying, credential stuffing, brute forcing attacks targeting privileged accounts**, also repeated multi-factor authentication challenges being denied by the user / failing ([Attackers have been seen abusing multi-factor authentication by leveraging “push” notifications on smartphones](https://www.mandiant.com/resources/russian-targeting-gov-business)).
     -   **Multi-factor authentication requests to a user repeatedly being denied or failing.**
     -   **The use of legacy protocols** to login to privileged accounts (Attackers bypass requirements for multi-factor authentication by authentication with legacy protocols)
     -   **Anomalous logins from on-premises infrastructure** (used by attackers to bypass Conditional Access rules and requirements for multi-factor authentication)

-   **Review Azure AD Audit logs to identify:**
     -   **Fake devices being associated to privileged accounts**
     -   **Privileged accounts being created**
     -   **Accounts being added to privileged roles**
     -   **Other suspicious events related to privileged accounts, for example passwords being reset, re-enrolling accounts for MFA**

-   **Review risk events and detections associated with privileged account logins**

### Hunt for hijacked Azure AD Applications and Service Principals 

-   **Identify Applications and Service Principal with sensitive "Application" Microsoft Graph API permissions configured, and other sensitive application specific API permissions**, including AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, and Mail.Read. 

-  **Identify Service Principals with both credentials and sensitive permissions** to identify the malicious addition of credentials to new or existing Service Principals including "first party" Microsoft / built-in by default Service Principals ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)) (AzureAD: Get-AzureADServicePrincipal -All $True) 

-  **Identify Applications with credentials and sensitive permissions** to identify the malicious addition of credentials to new or existing Applications ([T1098.001](https://attack.mitre.org/techniques/T1098/001/)) (AzureAD: Get-AzureADApplication -All $True)

-   **Review all Azure AD logs for suspicious sign-ins by Service Principals with sensitive permissions** to identify compromised services principals (including considering whether **third-party Service Principal credentials** have been compromised) 

-   **Review Azure AD Audit logs** to identify the malicous creation of Service Principals and Applications, the addition of credentials to Service Principals and Applications, and sensitive permissions being added to Applications or Service Principals.

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

-   **Review Azure Activity logs to identify any malicious changes to permissions on Azure resources** for example adding new owners to subscriptions or resource groups, or changing permissions on storage buckets.

-   **Review Azure Activity logs to identify whether the attacker used their access to compromise Azure services**, including by using the [Azure Run command](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/run-command) to execute commands on VMs, downloading of virtual machine images, creating SAS URLs, or listing storage accounts keys.

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

-   **Remove accounts from privileged Azure AD roles** unless strictly required.

-   **Ensure all privileged accounts have multi-factor authentication enforced (using verification codes or hardware tokens) and are not configured to sync with on-premises Active Directory domains.**

-   **Remove sensitive permissions from Service Principals** unless strictly required in order for the AAD applications to function.

-   **Create break glass Global Aministrator accounts and ensure that these are excluded from all Conditional Access policies**

-   **Reset passwords for known compromised accounts, revoke the account's Azure AD refresh tokens and disable registered devices** ([see this Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-revoke-access) on the different types of authentication tokens and how to revoke all access for a user)

-   **Reset passwords of all privileged Azure AD accounts, revoke refresh tokens and audit registered devices**

-   **Rotate credential material for any Service Principals that are members of privileged roles and revoke refresh tokens**

-   **Block legacy authentication methods and review conditional access policies that are configured**

-   **Assess what authentication material the attacker may have been able to access** with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. Access keys for Azure Storage accounts) and take steps to mitigate this risk.

-   **Assess what other authentication material the attacker would have been able to generate / steal** with the accounts they were able to compromise, and whether there was sufficient logging to confirm this (e.g. creating shared access signatures for Azure Storage accounts) and take steps to mitigate this risk.

### Active Directory 

-   **Remove domain administrator privileges from all on-premises user accounts and service accounts**, apart from those used by the remediation team and for break glass accounts.

-   **Identify, review and harden access to all on-premises Tier 0 systems**

-   **Remediate accounts in the on-premises environment**, including:  
    - Disable or reset the password of all known compromised accounts twice 
    - Resetting all privileged accounts  
    - Resetting the AZUREADSSOACC account  
    - Resetting the on-premises AD DS connector account  
    - Resetting the Azure AD connector account  
    - Resetting the on-premises ADSync Service Account  
    - Resetting the local accounts on DCs  
    - Rotating the token-signing certificate twice  
    - Resetting the Kerberos ticket granting ticket account twice  
    - Rotating secrets associated with remote access MFA token generation

-   **Rebuild all compromised systems**

-   **Reset VMware ESXi root account passwords**

-   **Restart all systems** to mitigate the risk of in-memory malware still running, for example Cobalt Strike.

-   **Re-establish federation trusts between on-premises Active Directory domains and Azure AD tenant**

## Assess data accessed and or exfiltrated by the attacker 

-   **Assess the business impact of incident** by investigating what data was accessed by the attacker.

## Improve security posture to defend against further attacks

-   **Remove delegated administrator permissions** from partner relationships, and migrate to [granular delegated admin privileges (GDAP)](https://docs.microsoft.com/en-us/partner-center/gdap-introduction) if access is still required.

-   **Add Azure AD P2 licenses for administrator accounts, configure Privileged Identity Manager (PIM) and remove all accounts from the Global Admin role** (except break glass accounts), set eligible assignments to accounts for Azure AD roles that can be activated for time limited periods. 

-   **Deploy Azure AD Password Protection** to detect and block known weak passwords.

-   **Perform an enterprise-wide passwords reset**, including resetting all service accounts and configuring employee accounts to change password at next logon.

-   **Configure [number matching for multifactor authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-mfa-number-match) push notifications** 

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

-   **Configure** [**Privileged Access Management**](https://techcommunity.microsoft.com/t5/microsoft-security-and/privileged-access-management-in-office-365-is-now-generally/ba-p/261751) **in Microsoft 365**

-   **Limit application consent policy to administrators**

-   **Block email forwarding to remote domains**

-   **Configure enhanced mailbox audit logging**, including MailItemsAccessed.

-   **Reduce the risk of phishing attacks,** including by deploying email tooling that restricts attachment file-types and scans for malicious content, and by deploying always-on web security tooling that blocks malicious content and website categories.

-   **Harden workstations used by employees**, including by hardening endpoints to restrict the execution of untrusted scripts and executables (including with EPP tooling, [WDAC and AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview) and by blocking [executables commonly used to circumvent these](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)), configuring [Attack Surface Reduction rules](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide), and removing local administrator privileges from standard accounts and restricting the execution of untrusted Microsoft Office macros.

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

-   Exporting via the Azure AD Console. Azure AD logs exported using this method are not stored in the same structure as those in Azure Sentinel. Logs can be exported in CSV and JSON with up to 100,000 records per export. 

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
