# Kerberos TGS was requested

### Event Description

* **Event ID 4769**: This event is logged whenever an account requests a Kerberos service ticket (TGS ticket). It provides details such as the requesting account, the service principal name (SPN), and the ticket encryption type. Monitoring this event is crucial for detecting abnormal service ticket requests, which may indicate lateral movement or attempts to exploit Kerberos (e.g., Pass-the-Ticket or Kerberoasting attacks).

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Simulating Normal Kerberos Service Ticket Requests**:

* Log in to a domain-joined machine.
* Access a network resource, such as a shared folder or a web application, that requires authentication using Kerberos.
* Check **Event Viewer** > **Windows Logs** > **Security** for **Event ID 4769**.
{% endtab %}

{% tab title="CMD" %}
We will try accessing a shared folder to help you get a Kerberos ticket.

```batch
net use \\domainserver\share
```
{% endtab %}

{% tab title="Powershell" %}
We will try accessing a shared folder to help you get a Kerberos ticket.

```powershell
New-PSDrive -Name "K" -PSProvider "FileSystem" -Root "\\fileserver\shared"
```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 29-11-2024 10:30:37 Microsoft Windows security auditing. 4769 Kerberos Service Ticket Operations

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4769" AND TransmittedServices="*@*" AND ServiceSid="*-502") AND  NOT ((TargetUserName="%allowed_unconstrained_accounts%" OR IpAddress="%domain_controllers_ips%"))
```
{% endcode %}

***

### Splunk Logs

```
11/28/2024 04:58:44 PM
LogName=Security
EventCode=4769
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=96678
Keywords=Audit Success
TaskCategory=Kerberos Service Ticket Operations
OpCode=Info
Message=A Kerberos service ticket was requested.

Account Information:
	Account Name:		Administrator@TEST.COM
	Account Domain:		TEST.COM
	Logon GUID:		{c0e261ec-fa4b-9d25-25a6-bb8f34bd4a80}

Service Information:
	Service Name:		WIN-3BK7E06Q35B$
	Service ID:		S-1-5-21-2889491314-2746541823-3071263440-1000

Network Information:
	Client Address:		::1
	Client Port:		0

Additional Information:
	Ticket Options:		0x40810000
	Ticket Encryption Type:	0x12
	Failure Code:		0x0
	Transited Services:	-
```

***

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

***

### Sigma Rules

<details>

<summary>Rubeus Kerberos unconstrained delegation abuse</summary>

```yaml
title: Rubeus Kerberos unconstrained delegation abuse
description: Detects scenarios where an attacker abuse Kerberos unconstrained delegation for domain persistence.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.credential_access
- attack.t1558
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TransmittedServices|contains: '@'
    ServiceSid|endswith: '-502' # Krbtgt account SID
  filter:
    - TargetUserName: '%allowed_unconstrained_accounts%' # User accounts allowed to perform unconstrained delegation
    - IpAddress: '%domain_controllers_ips%'              # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Accounts with unconstrained delegation enabled
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4769" AND TransmittedServices="*@*" AND ServiceSid="*-502") AND  NOT ((TargetUserName="%allowed_unconstrained_accounts%" OR IpAddress="%domain_controllers_ips%"))
```
{% endcode %}

</details>

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

<summary>Kerberoast ticket request detected</summary>

```yaml
title: Kerberoast ticket request detected
name: kerberoast_ticket_request
description: Detects scenarios where an attacker requests a Kerberoast ticket with low encryption to perform offline brutforce and forge a new ticket to get access to the targeted resource.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
  - https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus/
  - https://blog.harmj0y.net/redteaming/kerberoasting-revisited/
  - https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/
  - https://www.hackingarticles.in/as-rep-roasting/
  - https://adsecurity.org/?p=2293
  - https://adsecurity.org/?p=3458
  - https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
  - https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/
  - https://github.com/nidem/kerberoast
  - https://github.com/skelsec/kerberoast
  - https://posts.specterops.io/capability-abstraction-fbeaeeb26384
  - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
  - https://m365internals.com/2021/11/08/kerberoast-with-opsec/
  - https://redcanary.com/blog/marshmallows-and-kerberoasting/
  - https://www.semperis.com/blog/new-attack-paths-as-requested-sts/
  - https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus/
  - https://nored0x.github.io/red-teaming/Kerberos-Attacks-Kerbroasting/
tags:
  - attack.credential_access
  - attack.t1558.003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    #TicketOptions: # depending on the source/tool, the options may change.
    #- 0x40810000
    #- 0x40800000
    #- 0x40810010
    #- 0x40800010
    TicketEncryptionType: 0x17 # RC4-HMAC
    Status: 0x0 # Success
  filter:
    - ServiceName|endswith: "$" # Exclude computer account services
    - ServiceSid: "S-1-5-21-*-0" # Exclude domain Service
    - ServiceSid|endswith: "-502" # Exclude Krbtgt service
    - TargetUserName|contains: "$@" # Exclude computer accounts requests
    - IpAddress:
        - "::1"
        - "127.0.0.1"
        - "%domain_controllers_ips%"
    #- ServiceName NOT IN TargetUserName (NOT SUPPORTED BY ALL SIEM)
  condition: selection and not filter
falsepositives:
  - Applications using RC4 encryption (SAP, Azure AD, legacy applications...)
level: high

---
title: Kerberoast ticket request detected Count
status: experimental
correlation:
  type: value_count
  rules:
    - kerberoast_ticket_request
  group-by:
    - ServiceName
  timespan: 30m
  condition:
    gte: 2
    field: IpAddress
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4769 TicketEncryptionType=23 Status=0 NOT (ServiceName="*$" OR ServiceSid="S-1-5-21-*-0" OR ServiceSid="*-502" OR TargetUserName="*$@*" OR IpAddress IN ("::1", "127.0.0.1", "%domain_controllers_ips%"))
| bin _time span=30m
| stats dc(IpAddress) as value_count by _time ServiceName
| search value_count >= 2
```
{% endcode %}

</details>

<details>

<summary>Rubeus Kerberos constrained delegation abuse (S4U2Proxy)</summary>

```yaml
title: Rubeus Kerberos constrained delegation abuse (S4U2Proxy)
description: Detects scenarios where an attacker abuse Kerberos constrained delegation in order to escalate privileges.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.credential_access
- attack.t1558
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TransmittedServices|contains: '@'
  filter:
    - ServiceSid|endswith: '-502' # Krbtgt account SID is excluded as it may be related to "Unconstrained Domain Persistence" (see other rule)
    - TargetUserName: '%allowed_S4U2Proxy_accounts%' # User accounts allowed to perform constrained delegation
    - IpAddress: '%domain_controllers_ips%'          # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Accounts with constrained delegation enabled
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4769" AND TransmittedServices="*@*") AND  NOT ((ServiceSid="*-502" OR TargetUserName="%allowed_S4U2Proxy_accounts%" OR IpAddress="%domain_controllers_ips%"))
```
{% endcode %}

</details>

<details>

<summary>Kerberos key list attack for credential dumping</summary>

```yaml
title: Kerberos key list attack for credential dumping
description: Detects scenarios where an attacker attempts to forge a special Kerberos service ticket in order to extract credentials from Read Only Domain Controllers (RODC).
references:
- https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/
- https://www.tarlogic.com/blog/how-to-attack-kerberos/
tags:
- attack.credential_access
- attack.t1003 # credential dumping
- attack.t1558 # forget ticket
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    Status: 0x0 # Success
    TicketOptions: '0x10000' # proxiable ticket
  filter:
    - IpAddress: '%domain_controllers_ips%'     # reduce amount of false positives
    - TargetUserName: '%account_allowed_proxy%' # accounts allowed to perform proxiable requests
  condition: selection and not filter
falsepositives:
- Applications or services performing delegation activities, ADFS servers
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4769" AND Status="0" AND TicketOptions="0x10000") AND  NOT ((IpAddress="%domain_controllers_ips%" OR TargetUserName="%account_allowed_proxy%"))
```
{% endcode %}

</details>

<details>

<summary>Kerberos ticket without a trailing $ (CVE-2021-42278/42287)</summary>

```yaml
title: Kerberos ticket without a trailing $ (CVE-2021-42278/42287)
description: Detects scenarios where an attacker attempts to spoof the SAM account name of a a domain controller in order to impersonate it. Vulnerability comes from that computer accounts should have a trailing $ in their name (i.e. sAMAccountName attribute) but no validation process existed until the patch was released. During the offensive phase, attacker will create and rename the sAMAccountName of a computer account to look like the one of a domain controller.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.credential_access
- attack.t1558 # forged ticket
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_tgt:
    EventID: 4768
    Status: 0x0 # Success
    ServiceSid|endswith: '-502' # Krbtgt account SID
    #TargetUserName.lower() == Computer.split(".")[0].lower() # normal behavior would be that TargetUsername and Computer are different (DC01$ and DC01.domain.lan). Having both matching is suspicious.

  selection_tgs:
    EventID: 4769
    Status: 0x0 # Success
    ServiceName|endswith: $
    #TargetUserName.split("@")[0].lower() == Computer.split(".")[0].lower() # normal behavior would be that TargetUsername and Computer are different (DC01$@domain.lan vs DC01.domain.lan). Having both matching is suspicious.

  selection_host:
    TargetUserName|contains: "$"

  condition: (selection_tgt or selection_tgs) and not selection_host
falsepositives:
- None
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4768" AND Status="0" AND ServiceSid="*-502") OR (EventID="4769" AND Status="0" AND ServiceName="*$")) AND  NOT (TargetUserName="*$*")
```
{% endcode %}

</details>

<details>

<summary>Rubeus Kerberos unconstrained delegation abuse</summary>

```yaml
title: Rubeus Kerberos unconstrained delegation abuse
description: Detects scenarios where an attacker abuse Kerberos unconstrained delegation for domain persistence.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.credential_access
- attack.t1558
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TransmittedServices|contains: '@'
    ServiceSid|endswith: '-502' # Krbtgt account SID
  filter:
    - TargetUserName: '%allowed_unconstrained_accounts%' # User accounts allowed to perform unconstrained delegation
    - IpAddress: '%domain_controllers_ips%'              # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Accounts with unconstrained delegation enabled
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4769" AND TransmittedServices="*@*" AND ServiceSid="*-502") AND  NOT ((TargetUserName="%allowed_unconstrained_accounts%" OR IpAddress="%domain_controllers_ips%"))
```
{% endcode %}

</details>

<details>

<summary>SharpHound host enumeration over Kerberos</summary>

```yaml
title: SharpHound host enumeration over Kerberos
name: sharphound_enumeration_kerberos
description: Detect if a source host is requesting multiple Kerberos Service tickets (TGS) for different assets in a short period of time.
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
  - https://www.splunk.com/en_us/blog/security/sharing-is-not-caring-hunting-for-file-share-discovery.html
tags:
  - attack.discovery
  - attack.t1069.002
  - attack.t1087.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    ServiceName|endswith: "$"
    Status: 0x0
  filter:
    - IpAddress:
        - "::1"
        - "%domain_controllers_ip%"
    - TargetUserName|contains: "$@" # excludes computer accounts
  condition: selection and not filter
  timeframe: 5m
falsepositives:
  - Administrator activity, backup software
level: medium

---
title: SharpHound host enumeration over Kerberos Count
status: experimental
correlation:
  type: value_count
  rules:
    - sharphound_enumeration_kerberos
  group-by:
    - ServiceName
  timespan: 15m
  condition:
    gte: 20
    field: IpAddress
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4769 ServiceName="*$" Status=0 NOT (IpAddress IN ("::1", "%domain_controllers_ip%") OR TargetUserName="*$@*")

| bin _time span=5m
| stats dc(IpAddress) as value_count by _time ServiceName

| search value_count >= 20
```
{% endcode %}

</details>

***
