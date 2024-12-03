# Account Failed to Log on

### Event Description

* **Event ID 4625**: This event is logged when an account fails to log on. It captures details such as the account name, domain, logon type, source network address, and failure reason. Monitoring failed logon attempts is critical for identifying potential brute force attacks, unauthorized access attempts, or misconfigured accounts.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* Attempt to log in with an incorrect password multiple times on a Windows machine or domain controller.
* Use tools such as **Remote Desktop** or **Windows Security Prompt** or **Local Login** to simulate various logon types (e.g., interactive, network).
{% endtab %}

{% tab title="CMD" %}
* Open CMD as a standard user.
*   Use the `runas` command to simulate a login attempt:

    ```batch
    runas /user:NonExistentUser cmd.exe
    ```

    * Replace `NonExistentUser` with a username that does not exist or an incorrect username for an existing account.
* When prompted for a password, enter a random incorrect password.
{% endtab %}

{% tab title="Powershell" %}
* Open PowerShell as a standard user or administrator.
*   Use the `Start-Process` cmdlet to simulate a failed logon:

    ```powershell
    Start-Process -FilePath "cmd.exe" -Credential (New-Object System.Management.Automation.PSCredential("InvalidUser", (ConvertTo-SecureString "WrongPassword" -AsPlainText -Force)))
    ```

    * Replace `"InvalidUser"` with a nonexistent or incorrect username.
    * Replace `"WrongPassword"` with any random incorrect password.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Capture Additional Details:**

* Note the **Logon Type** in the event details to identify the context of the failed attempt:
  * **Logon Type 2**: Interactive (e.g., local logon).
  * **Logon Type 3**: Network (e.g., accessing shared resources).
  * **Logon Type 10**: Remote Interactive (e.g., Remote Desktop).
* Record the **Failure Reason** and **Source Network Address** for investigation.
{% endhint %}

***

### Event Viewer Logs

> Audit Failure 15-11-2024 12:52:05 Microsoft Windows security auditing. 4625 Logon

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode=4625 
| search Account_Name!=*$ AND Account_Name!="-"
| rename Account_Name as src_user
| stats count by index src_user Account_Domain EventCode Failure_Reason Workstation_Name sourcetype
```
{% endcode %}

***

### Splunk Logs

```
12/03/2024 11:54:28 AM
LogName=Security
EventCode=4625
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=124703
Keywords=Audit Failure
TaskCategory=Logon
OpCode=Info
Message=An account failed to log on.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0xA7382

Logon Type:			2

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		aghosh0605
	Account Domain:		TEST

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x198
	Caller Process Name:	C:\Windows\System32\svchost.exe

Network Information:
	Workstation Name:	WIN-3BK7E06Q35B
	Source Network Address:	::1
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		seclogo
	Authentication Package:	Negotiate
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0
```

### Splunk Alerts

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

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

<summary>Brutforce enumeration on Windows OpenSSH server with non existing user</summary>

```yaml
title: Brutforce enumeration on Windows OpenSSH server with non existing user
name: openssh_bruteforce_non_existing_user
description: Detects scenarios where an attacker attempts to SSH brutforce a Windows OpenSSH server with non existing users.
remarks: This requires to have previously enabled the builtin OpenSSH server or to have installed the "OpenSSH-Win64" component. IpAddress or Workstation fields may be empty. In case Workstation field is not empty, be aware that it may wrongly report the source host. Also note that SSH logins are reported with logon type 8 (clear text). For reliable source IP information, use the logs from the OpenSSH channel, event ID 4.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://winaero.com/enable-openssh-server-windows-10/
  - https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
  - https://virtualizationreview.com/articles/2020/05/21/ssh-server-on-windows-10.aspx
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
    EventID: 4625
    SubStatus: "0xc0000064" # Non existing user
    ProcessName|endswith: '\sshd.exe' # Can be "C:\Program Files\OpenSSH-Win64\sshd.exe" or "C:\Windows\system32\OpenSSH\sshd.exe"
  condition: selection
falsepositives:
  - None
level: high

---
title: Brutforce enumeration on Windows OpenSSH server with non existing user Count
status: experimental
correlation:
  type: value_count
  rules:
    - openssh_bruteforce_non_existing_user # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4625 SubStatus="0xc0000064" ProcessName="*\\sshd.exe"
| bin _time span=30m
| stats dc(TargetUserName) as value_count by _time Computer
| search value_count >= 20
```
{% endcode %}

</details>

<details>

<summary>Brutforce on Windows OpenSSH server with valid users</summary>

```yaml
title: Brutforce on Windows OpenSSH server with valid users
name: bruteforce_openssh_vaild_users
description: Detects scenarios where an attacker attempts to SSH brutforce a Windows OpenSSH server with a valid user.
remarks: This requires to have previously enabled the builtin OpenSSH server or to have installed the "OpenSSH-Win64" component. IpAddress or Workstation fields may be empty. In case Workstation field is not empty, be aware that it may wrongly report the source host. Also note that SSH logins are reported with logon type 8 (clear text). For reliable source IP information, use the logs from the OpenSSH channel, event ID 4.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://winaero.com/enable-openssh-server-windows-10/
  - https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
  - https://virtualizationreview.com/articles/2020/05/21/ssh-server-on-windows-10.aspx
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
    EventID: 4625
    SubStatus: "0xc000006A" # invalid password | Failure code can be defined in "Status" or "Substatus" fields. Usually, if Substatus == 0x0, refers to Status.
    ProcessName|endswith: # Can be "C:\Program Files\OpenSSH-Win64\sshd.exe" or "C:\Windows\system32\OpenSSH\sshd.exe"
      - '\sshd.exe'
      - '\ssh.exe'
  condition: selection
falsepositives:
  - None
level: high

---
title: Brutforce on Windows OpenSSH server with valid users Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_openssh_vaild_users # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: EventRecordID
level: high

```

<pre class="language-splunk-spl"><code class="lang-splunk-spl">source="WinEventLog:Security" EventCode=4625 SubStatus="0xc000006A" ProcessName IN ("*\\sshd.exe", "*\\ssh.exe")
<strong>| bin _time span=30m
</strong>| stats dc(EventRecordID) as value_count by _time Computer
| search value_count >= 20
</code></pre>

</details>

<details>

<summary>Brutforce enumeration with non existing users (logi</summary>

```yaml
title: Brutforce enumeration with non existing users (login)
name: login_non_existing_user
description: Detects scenarios where an attacker attempts to enumerate potential existing users, resulting in failed logins with unexisting or invalid accounts.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
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
    EventID: 4625
    SubStatus: "0xc0000064" # user not found | Failure code can be defined in "Status" or "Substatus" fields. Usually, if Substatus == 0x0, refers to Status.
  filter:
    IpAddress: "%domain_controllers_ips%" # reduce amount of false positives
  condition: selection and not filter
falsepositives:
  - Missconfigured application
level: high

---
title: Brutforce enumeration with non existing users (login) Count
status: experimental
correlation:
  type: value_count
  rules:
    - login_non_existing_user # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName
level: high

```

```splunk-spl
source="WinEventLog:Security" EventCode=4625 SubStatus="0xc0000064" NOT IpAddress="%domain_controllers_ips%"
| bin _time span=30m
| stats dc(TargetUserName) as value_count by _time Computer
| search value_count >= 20
```

</details>

