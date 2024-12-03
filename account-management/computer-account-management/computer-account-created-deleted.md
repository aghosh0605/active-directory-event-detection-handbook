# Computer Account Created/Deleted

### Event Description

* **Event ID 4741**: This event is logged when a new computer account is created in Active Directory. It captures information about the account created, the user initiating the action, and the domain where the account was created. Monitoring this event helps detect unauthorized additions of computer accounts that could lead to malicious activities like lateral movement.
* **Event ID 4743**: This event is generated when a computer account is deleted in Active Directory. It includes details about the deleted account, the initiator of the action, and the domain affected. Tracking this event ensures that critical computer accounts are not removed without proper authorization.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Simulating Computer Account Creation:**
  * Log in to a system with privileges to manage Active Directory.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Navigate to the **Computers** container or any Organizational Unit (OU).
  * Right-click and select **New** > **Computer**.
  * Enter the name of the new computer account and complete the creation process.
  * Check **Event Viewer** > **Windows Logs** > **Security** on the domain controller to verify **Event ID 4741** is logged.
* **Simulating Computer Account Deletion:**
  * Log in to a system with privileges to manage Active Directory.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Navigate to the **Computers** container or the specific OU.
  * Select a computer account and delete it.
  * Confirm that **Event ID 4743** is generated in **Event Viewer** on the domain controller.
{% endtab %}

{% tab title="CMD" %}
* **Open CMD with Administrative Privileges on the DC**.
*   Use the following command to delete the computer account:

    ```batch
    dsadd computer "CN=TestComputer,OU=Computers,OU=Blue,DC=test,DC=com"
    ```

    Delete the account with the below command:

    ```batch
    dsrm "CN=TestComputer,OU=Computers,OU=Blue,DC=test,DC=com"
    ```
{% endtab %}

{% tab title="Powershell" %}
* **Open PowerShell with Administrative Privileges on the DC**.
*   Use the following command to create a computer account:

    ```powershell
    New-ADComputer -Name "TestComputer" -Path "OU=Computers,DC=example,DC=com"
    ```

    Delete the account with the below command:

    ```powershell
    Remove-ADComputer -Identity "TestComputer"
    ```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 02-12-2024 15:37:13 Microsoft Windows security auditing. 4741 Computer Account Management\
> Audit Success 02-12-2024 15:51:35 Microsoft Windows security auditing. 4743 Computer Account Management

***

### Splunk Queries

```splunk-spl
index=ad-test EventCode IN (4741,4743) 
| stats count by index sourcetype src_user EventCode dest user host ComputerName
```

***

### Splunk Logs

{% tabs %}
{% tab title="4741" %}
```
12/02/2024 03:55:13 PM
LogName=Security
EventCode=4741
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=117608
Keywords=Audit Success
TaskCategory=Computer Account Management
OpCode=Info
Message=A computer account was created.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x3CFF4

New Computer Account:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1114
	Account Name:		TestComputer$
	Account Domain:		TEST

Attributes:
	SAM Account Name:	TestComputer$
	Display Name:		-
	User Principal Name:	-
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	515
	AllowedToDelegateTo:	-
	Old UAC Value:		0x0
	New UAC Value:		0x81
	User Account Control:	
		Account Disabled
		'Workstation Trust Account' - Enabled
	User Parameters:	-
	SID History:		-
	Logon Hours:		<value not set>
	DNS Host Name:		-
	Service Principal Names:	-

Additional Information:
	Privileges		-
```
{% endtab %}

{% tab title="4743" %}
```
12/02/2024 03:51:35 PM
LogName=Security
EventCode=4743
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=117525
Keywords=Audit Success
TaskCategory=Computer Account Management
OpCode=Info
Message=A computer account was deleted.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x3CFF4

Target Computer:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1113
	Account Name:		TESTCOMPUTER$
	Account Domain:		TEST

Additional Information:
	Privileges:		-
```
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>Suspicious computer account created by a computer account</summary>

```yaml
title: Suspicious computer account created by a computer account
description: Detects scenarios where an attacker abuse MachineAccountQuota privilege and pre-create a computer object for abusing RBCD delegation.
references:
- https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
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
    EventID: 4741
    SubjectUserName|endswith: '$'
    SubjectUserSid|startswith: 'S-1-5-21-' # SYSTEM account 'S-1-5-18' would trigger a false positive
    TargetUserName|endswith: '$'
  condition: selection
falsepositives:
- Offline domain join host  
- Windows Autopilot Hybrid Azure AD Join
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4741" AND SubjectUserName="*$" AND SubjectUserSid="S-1-5-21-*" AND TargetUserName="*$")
```
{% endcode %}

</details>

<details>

<summary>Computer account created with privileges</summary>

```yaml
title: Computer account created with privileges
description: Detects scenarios where an attacker creates a computer account with privileges for later exploitation.
correlation: correlate with ID 4763 (privileges) using field SubjectLogonId. See rule "Privilege SeMachineAccountPrivilege abuse" for advance correlation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.t1136 # user creation
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4741
  filter:
    PrivilegeList: "-" # Interesting privileges would be "SeMachineAccountPrivilege"
  condition: selection and not filter
falsepositives:
- None
level: high
```

```splunk-spl
source=WinEventLog:Security AND EventID="4741" AND  NOT (PrivilegeList="-")
```

</details>

<details>

<summary>Privilege SeMachineAccountPrivilege abuse</summary>

```yaml
title: Privilege SeMachineAccountPrivilege abuse
description: Detects scenarios where an attacker abuse the SeMachineAccountPrivilege which allows per default any authenticated user to join a computer to the domain. Later on, this computer account can be manipulated in order to elevate privileges.
requirements: despite of this event marked as a "sensitive privilege", I was only able to trigger it by having the audit for "non sensitive privileges" activated.
correlation: correlate with ID 4741 (computer created) using field SubjectLogonId. See rule "Computer account created with privileges" for advance correlation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.privilege_escalation
- attack.t1068
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4673
    PrivilegeList: SeMachineAccountPrivilege
    #ProcessName|endswith: \Windows\System32\lsass.exe
  filter:
    - SubjectUserSid: "S-1-5-18"
    - SubjectUserName: '%admin_acounts%'
  condition: selection and not filter
falsepositives:
- Users (shouldn't) or administrators joining a computer to the domain, server provisionning software
level: medium

```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4673" AND PrivilegeList="SeMachineAccountPrivilege") AND  NOT ((SubjectUserSid="S-1-5-18" OR SubjectUserName="%admin_acounts%"))
```
{% endcode %}

</details>

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
source=WinEventLog:Security AND (EventID="4720" AND SubjectUserName="*$" AND SubjectUserSid="S-1-5-21-*")
```
{% endcode %}

</details>

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4743](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4743)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741)
3. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754539(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754539\(v=ws.11\))
4. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731865(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731865\(v=ws.11\))
5. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer?view=windowsserver2025-ps)
6. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputer?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputer?view=windowsserver2025-ps)
