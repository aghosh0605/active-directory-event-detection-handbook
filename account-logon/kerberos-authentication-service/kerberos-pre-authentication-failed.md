# Kerberos pre-authentication failed

### Event Description

* **Event ID 4771**: This event is logged when a Kerberos pre-authentication request fails. It indicates that the Key Distribution Center (KDC) was unable to validate the pre-authentication data provided by a user or computer during the Kerberos authentication process. This event often occurs due to incorrect passwords or account lockouts and is critical for identifying failed authentication attempts in a Kerberos environment.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* Lock the system (`Win + L`) or log off.
* At the logon screen, type the correct **username** but an **incorrect password** for a domain account.
* Press **Enter**.
{% endtab %}

{% tab title="CMD" %}
* Open CMD as a standard user.
* Attempt to log in with an incorrect password using an account configured for Kerberos authentication.
*   Alternatively, use PowerShell to generate authentication requests with incorrect credentials:

    ```batch
    :: Remove cached credentails with klist
    klist purge
    runas /user:<domain>\<username> cmd
    ```

    Enter an incorrect password when prompted.
{% endtab %}

{% tab title="Powershell" %}
Use the `Start-Process` cmdlet to simulate a failed Kerberos authentication:

```powershell
klist purge
Start-Process -FilePath "cmd.exe" -Credential (New-Object System.Management.Automation.PSCredential("DOMAIN\InvalidUser", (ConvertTo-SecureString "WrongPassword" -AsPlainText -Force)))
```

* Replace `DOMAIN` with the actual domain name.
* Replace `InvalidUser` with a nonexistent domain account or an incorrect username for an existing account.
* Replace `"WrongPassword"` with an invalid password.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
The **Source** and **Logon Type** in the event depend on how the logon was attempted.

* GUI logons are **Type 2 (Interactive)**.
* CMD and PowerShell logons are **Type 3 (Network)**.
* **Failure Code**, such as:
  * `0x12` (Account disabled).
  * `0x18` (Incorrect password).
{% endhint %}

***

### Event Viewer Logs

> Audit Failure 03-12-2024 13:55:16 Security-Auditing 4771 Kerberos Authentication Service

***

### Splunk Queries

```splunk-spl
index=ad-test EventCode=4771 Account_Name!=*$ 
| stats count by index, EventCode, Account_Name, sourcetype
| rename Account_Name as src_user
```

### Splunk Logs

```
12/03/2024 01:55:16 PM
LogName=Security
EventCode=4771
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=127527
Keywords=Audit Failure
TaskCategory=Kerberos Authentication Service
OpCode=Info
Message=Kerberos pre-authentication failed.

Account Information:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1104
	Account Name:		aghosh0605

Service Information:
	Service Name:		krbtgt/test.com

Network Information:
	Client Address:		::1
	Client Port:		0

Additional Information:
	Ticket Options:		0x40810010
	Failure Code:		0x18
	Pre-Authentication Type:	2

Certificate Information:
	Certificate Issuer Name:		
	Certificate Serial Number: 	
	Certificate Thumbprint:		

```

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>Active Directory honeypot used for lateral movement</summary>

```yaml
title: Active Directory honeypot used for lateral movement
description: Detects scenarios where an attacker is using
requirements: ensure that those accounts are "attractive", documented, do not create any breach and cannot be used against your organization.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- http://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://jblog.javelin-networks.com/blog/the-honeypot-buster/
tags:
- attack.lateral_movement
- attack.t1021
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4624
      - 4625
      - 4768
      - 4769
      - 4770
      - 4771
      - 5140
      - 5145
    TargetUserName: '%honeypot_account_list%'
  condition: selection
falsepositives:
- pentest
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4624" OR EventID="4625" OR EventID="4768" OR EventID="4769" OR EventID="4770" OR EventID="4771" OR EventID="5140" OR EventID="5145") AND TargetUserName="%honeypot_account_list%")
```
{% endcode %}

</details>

<details>

<summary>Brutforce enumeration with unexisting users (Kerberos)</summary>

```yaml
title: Brutforce enumeration with unexisting users (Kerberos)
name: bruteforce_non_existing_users_kerberos
description: Detects scenarios where an attacker attempts to enumerate potential existing users, resulting in failed Kerberos TGT requests with unexisting or invalid accounts.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://github.com/ropnop/kerbrute
tags:
  - attack.credential_access
  - attack.t1110
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4771
      - 4768
    Status: "0x6" # KDC_ERR_C_PRINCIPAL_UNKNOWN
  filter:
    - IpAddress: "%domain_controllers_ips%" # reduce amount of false positives
    - TicketOptions: 0x50800000 # covered by Kerbrute rule
  condition: selection and not filter
falsepositives:
  - Missconfigured application or identity services
level: high

---
title: Brutforce enumeration with unexisting users (Kerberos) Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_non_existing_users_kerberos # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName # Count how many failed logins with non existing users were reported on the domain controller.
level: high

```

```splunk-spl
source="WinEventLog:Security" EventCode IN (4771, 4768) Status="0x6" NOT (IpAddress="%domain_controllers_ips%" OR TicketOptions=1350565888)
| bin _time span=30m
| stats dc(TargetUserName) as value_count by _time Computer
| search value_count >= 20
```

</details>

<details>

<summary>Kerberos enumeration with existing/unexisting users (Kerbrute)</summary>

```yaml
title: Kerberos enumeration with existing/unexisting users (Kerbrute)
name: kerbrute_enumeration
description: Detects scenarios where an attacker attempts to enumerate existing or non existing users using "Kerbrute". This use case can also be related to spot vulnearbility "MS14-068".
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://github.com/ropnop/kerbrute
  - https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
tags:
  - attack.credential_access
  - attack.t1110
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4771
      - 4768
    Status: "0x6" # KDC_ERR_C_PRINCIPAL_UNKNOWN
    TicketOptions: 0x50800000
  filter:
    - IpAddress: "%domain_controllers_ips%" # reduce amount of false positives
    - TargetUserName: "%account_allowed_proxy%" # accounts allowed to perform proxiable requests
  condition: selection and not filter
falsepositives:
  - Missconfigured application or identity services
level: high

---
title: Kerberos enumeration with existing/unexisting users (Kerbrute) Count
status: experimental
correlation:
  type: value_count
  rules:
    - kerbrute_enumeration # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName # Count how many failed logins were reported on the domain controller.
level: high

```

<pre class="language-splunk-spl"><code class="lang-splunk-spl">source="WinEventLog:Security" EventCode IN (4771, 4768) Status="0x6" TicketOptions=1350565888 NOT (IpAddress="%domain_controllers_ips%" OR TargetUserName="%account_allowed_proxy%")
<strong>| bin _time span=30m
</strong>| stats dc(TargetUserName) as value_count by _time Computer
| search value_count >= 20
</code></pre>

</details>

### _References_

1. [_https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771_](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
2. [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)

***
