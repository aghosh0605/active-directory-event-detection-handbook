# User Created/Deleted

Event Description

* **Event ID 4720**: This event is generated when a new user account is created in Active Directory. It includes details such as the user who created the account, the name of the new account, and the time of creation.
* **Event ID 4726**: This event is logged when a user account is deleted. It records the user who initiated the deletion, the name of the account deleted, and the timestamp.

Monitoring these events is essential for tracking user lifecycle changes, which can help detect unauthorized account creation or deletion in the organization.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **User Creation**:
  * Log in to a domain controller with appropriate administrative privileges.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Right-click on an Organizational Unit (OU) where you want to create the user.
  * Select **New > User** and follow the prompts to create a new user account.
  * Once created, verify that **Event ID 4720** is generated in the Security log.
* **User Deletion**:
  * In **ADUC**, locate the user account created in the previous step.
  * Right-click on the user account and select **Delete**. Confirm the deletion.
  * Check the Security log to ensure **Event ID 4726** is recorded for this action.
{% endtab %}

{% tab title="CMD net.exe" %}
```batch
:: Create a user account
net user /add /domain testuser "test@password123"
:: Delete a user account
net user /delete /domain testuser
```
{% endtab %}

{% tab title="Powershell" %}
{% code overflow="wrap" %}
```powershell
# Create a user account
New-ADUser -Name 'testuser' -AccountPassword (ConvertTo-SecureString 'test@password123' -AsPlainText -Force) -Enabled $true

# Delete a user account
Remove-ADUser -Identity testuser
```
{% endcode %}
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 12-11-2024 01:07:56 Microsoft Windows security auditing. 4720 User Account Management\
> Audit Success 12-11-2024 01:08:42 Microsoft Windows security auditing. 4726 User Account Management

### Splunk Queries

This query searches for all instances of new user account creation and deletion:

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN (4720,4726) |rename user as targetuser| stats  values(ComputerName) as ComputerName count by index  sourcetype EventCode src_user targetuser
```
{% endcode %}

### Splunk logs

{% tabs %}
{% tab title="User Create" %}
```
11/13/2024 05:38:40 PM
LogName=Security
EventCode=4720
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=34334
Keywords=Audit Success
TaskCategory=User Account Management
OpCode=Info
Message=A user account was created.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0x3E7B1

New Account:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1108
	Account Name:		testuser
	Account Domain:		TEST

Attributes:
	SAM Account Name:	testuser
	Display Name:		<value not set>
	User Principal Name:	-
	Home Directory:		<value not set>
	Home Drive:		<value not set>
	Script Path:		<value not set>
	Profile Path:		<value not set>
	User Workstations:	<value not set>
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	513
	Allowed To Delegate To:	-
	Old UAC Value:		0x0
	New UAC Value:		0x15
	User Account Control:	
		Account Disabled
		'Password Not Required' - Enabled
		'Normal Account' - Enabled
	User Parameters:	<value changed, but not displayed>
	SID History:		-
	Logon Hours:		<value not set>

Additional Information:
	Privileges		-
```
{% endtab %}

{% tab title="User Delete" %}
```
11/12/2024 03:35:03 PM
LogName=Security
EventCode=4726
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=25186
Keywords=Audit Success
TaskCategory=User Account Management
OpCode=Info
Message=A user account was deleted.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0xDD477

Target Account:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1106
	Account Name:		eyhello
	Account Domain:		TEST

Additional Information:
	Privileges	-
```
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>User account created by a computer account</summary>

```yaml
title: User account created by a computer account
description: Detects scenarios where an attacker would abuse some privileges while realying host credentials to escalate privileges.
references:
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741
tags:
- attack.persistence
- attack.t1136 # user creation
- attack.defense_evesion
- attack.t1036 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    SubjectUserName|endswith: '$' # Computer account
    SubjectUserSid|startswith: 'S-1-5-21-' # SYSTEM account 'S-1-5-18' would trigger a false positive
  filter:
    TargetUserName|endswith: '$' # covered in another rule: User account creation disguised in a computer account
  condition: selection
falsepositives:
- Exchange servers
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4720 SubjectUserName="*$" SubjectUserSid="S-1-5-21-*"
```
{% endcode %}

</details>

<details>

<summary>User enumeration and creation related to Manic Menagerie 2.0 (via cmdline)</summary>

```yaml
title: User enumeration and creation related to Manic Menagerie 2.0 (via cmdline)
description: Detects user enumeration and/or creation performed by Manic Menagerie.
references:
- https://unit42.paloaltonetworks.com/manic-menagerie-targets-web-hosting-and-it/
- https://www.cyber.gov.au/sites/default/files/2023-03/report_manic_menagerie.pdf
- https://csl.com.co/rid-hijacking/
tags:
- attack.persistence
- attack.t1136.001
author: mdecrevoisier
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \net1.exe
      - \net.exe
    CommandLine|contains:
      - iis_uses
      - iis_user
  condition: selection
falsepositives:
- Administrator activity 
level: medium

```

{% code overflow="wrap" %}
```splunk-spl
Image IN ("*\\net1.exe", "*\\net.exe") CommandLine IN ("*iis_uses*", "*iis_user*")
```
{% endcode %}

</details>

<details>

<summary>User account creation disguised in a computer account</summary>

```yaml
title: User account creation disguised in a computer account
description: Detects scenarios where an attacker creates a user account that fakes a computer account.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://www.securonix.com/blog/securonix-threat-labs-security-advisory-threat-actors-target-mssql-servers-in-dbjammer-to-deliver-freeworld-ransomware/
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.t1136 # user creation
- attack.defense_evesion
- attack.t0136 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:

  selection_creation:
    EventID: 4720 # User account creation
    TargetUserName|endswith: '$'

  selection_renamed:
    EventID: 4781 # User account name change
    NewTargetUserName|endswith: '$' 

  filter:
    OldTargetUserName|endswith: '$' 

  condition: selection_creation or (selection_renamed and not filter)
falsepositives:
- None
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" (EventCode=4720 TargetUserName="*$") OR (EventCode=4781 NewTargetUserName="*$" NOT OldTargetUserName="*$")
```
{% endcode %}

</details>

<details>

<summary>User creation via commandline</summary>

```yaml
title: User creation via commandline
description: Detects scenarios where an attacker attempts to create a user via commandline.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html
- https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
- https://attack.mitre.org/software/S0039/
- https://regex101.com/r/S6vTNM/1
tags:
- attack.persistence
- attack.t1136.001
- attack.t1136.002
author: mdecrevoisier
logsource:
  product: windows
  category: process_creation
detection:
  selection: # Full command example: 'net user <username> <password> /ADD'
    NewProcessName|endswith:
      - \net1.exe
      - \net.exe
    CommandLine|contains|all:
      - net
      - user
      - add
  condition: selection
falsepositives:
- Pentest
- Administrator activity
level: high
```

{% code overflow="wrap" %}
```splunk-spl
NewProcessName IN ("*\\net1.exe", "*\\net.exe") CommandLine="*net*" CommandLine="*user*" CommandLine="*add*"
```
{% endcode %}

</details>

<details>

<summary>Fortinet APT group abuse on Windows (user)</summary>

```yaml
title: Fortinet APT group abuse on Windows (user)
description: Detects scenarios where APT actors exploits Fortinet vulnerabilities to gain access into Windows infrastructure.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/EVTX_full_APT_attack_steps
- https://www.aha.org/system/files/media/file/2021/05/fbi-flash-tlp-white-apt-actors-exploiting-fortinet-vulnerabilities-to-gain-access-for-malicious-activity-5-27-21.pdf
- https://www.securityweek.com/fbi-shares-iocs-apt-attacks-exploiting-fortinet-vulnerabilities
tags:
- attack.persistence
- attack.t1136
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    TargetUserName:
      - elie
      - WADGUtilityAccount
  condition: selection
falsepositives:
- None
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4720 TargetUserName IN ("elie", "WADGUtilityAccount")
```
{% endcode %}

</details>

<details>

<summary>Hidden account creation (with fast deletion)</summary>

```yaml
title: Hidden account creation (with fast deletion)
description: Detects scenarios where an attacker creates a hidden local account. See also rule "User account creation disguised in a computer account".
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://github.com/wgpsec/CreateHiddenAccount
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.t1136 # user creation
- attack.defense_evesion
- attack.t0136 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_create:
    EventID: 4720
  selection_delete:
    EventID: 4726
  filter:
    Computer: '%domain_controllers%'
  condition: selection_create and selection_delete and not filter # requires grouping over 'TargetSid' to not mix different user accounts
  timeframe: 1m
falsepositives:
- IAM account lifecycle software
level: medium
```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4720 EventCode=4726 NOT Computer="%domain_controllers%"
```
{% endcode %}

</details>

***

### References

1. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865\(v=ws.11\))
3. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2022-ps)
4. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
5. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726)
