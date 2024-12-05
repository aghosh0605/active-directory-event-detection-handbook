# User Password Changed/Reset

### Event Description

* **Event ID 4723**: This event is logged when a user attempts to change their own password. It includes details such as the user’s account name and the account domain. Monitoring this event helps detect unauthorized or unexpected password changes by regular users, which could indicate potential account misuse.
* **Event ID 4724**: This event is generated when an administrator or another privileged user attempts to reset a user’s password. The event details include the target account and the account name of the initiator. Monitoring this event is crucial for tracking password reset activities, especially on sensitive accounts, as it could indicate privilege abuse or unauthorized activity.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Simulating a User Password Change**:
  * Log in as a regular user to simulate a password change.
  * Press `Ctrl + Alt + Del` and select **Change a password**.
  * Follow the prompts to change the password.
  * Verify that **Event ID 4723** is logged in **Event Viewer** > **Windows Logs** > **Security**.
* **Simulating an Administrator Password Reset**:
  * Log in to a domain controller or a system with administrator privileges.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Right-click on a user account and select **Reset Password**.
  * Enter a new password and confirm the reset.
  * Check **Event Viewer** to confirm **Event ID 4724** is logged.
{% endtab %}

{% tab title="CMD" %}
```batch
:: Reset a user password
net user krbtgt "NewPassword@123"
```

For changing user passwords please follow the GUI method. Only reset can be done from the command line.
{% endtab %}

{% tab title="Powershell" %}
{% code overflow="wrap" %}
```powershell
#Change User Password
Set-ADAccountPassword -Identity testuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)

#Reset User Password
Set-ADAccountPassword krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText “NewP@ssw0rd123” -Force -Verbose) –PassThru
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
Please be cautious before running the reset password command as it contains krbtgt as the username and it may break your system.
{% endhint %}

***

### Event Viewer Logs

> Audit Success 14-11-2024 11:29:12 Microsoft Windows security auditing. 4723 User Account Management\
> Audit Success 14-11-2024 11:01:50 Microsoft Windows security auditing. 4724 User Account Management

***

### Splunk Queries

Check if any password change or reset happened for any user.

{% code overflow="wrap" %}
```splunk-spl
index="ad-test" EventCode IN(4723,4724)
|stats values(LogName) as LogName,values(src_user) as src_user,values(ComputerName) as ComputerName,values(signature) as signature,values(Message) as Message,values(status) as status,values(TaskCategory) as TaskCategory,values(action) as action count by index sourcetype host EventCode user
```
{% endcode %}

The Splunk query to detect if the KRBTGT account password was reset.

{% code overflow="wrap" %}
```splunk-spl
index="ad-test" user=krbtgt EventCode IN (4724)|eval user=lower(user), src_user=lower(src_user)| stats values(EventCode) as event_code values(src_user) as src_user values(result) as signature count by index sourcetype host ComputerName user action status
```
{% endcode %}

***

### Splunk Logs

{% tabs %}
{% tab title="Password Change" %}
```
11/14/2024 11:29:12 AM
LogName=Security
EventCode=4723
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=37092
Keywords=Audit Success
TaskCategory=User Account Management
OpCode=Info
Message=An attempt was made to change an account's password.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0x349A70

Target Account:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST

Additional Information:
	Privileges		-
```
{% endtab %}

{% tab title="Password Reset" %}
```
11/14/2024 11:01:50 AM
LogName=Security
EventCode=4724
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=35980
Keywords=Audit Success
TaskCategory=User Account Management
OpCode=Info
Message=An attempt was made to reset an account's password.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0x81195

Target Account:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-502
	Account Name:		krbtgt
	Account Domain:		TEST
```
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>Bruteforce via password reset</summary>

```yaml
title: Bruteforce via password reset
name: bruteforce_password_reset
description: Detects if a attacker attempts to reset multiple times a user password to perform a bruteforce attack.
references:
  - https://twitter.com/mthcht/status/1705164058343756005?s=08
tags:
  - attack.credential_access
  - attack.t1110.001 # brutforce: Password Guessing
  - attack.t1110.003 # brutforce: Password spraying
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4723 # reset of own user's password
      - 4724 # reset of user's password by another user
  condition: selection
falsepositives:
  - ADFS, DirSync
level: informational

---
title: Bruteforce via password reset Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_password_reset
  group-by:
    - TargetSid
  timespan: 10m
  condition:
    gte: 10
    field: host
level: high

```

```splunk-spl
source="WinEventLog:Security" EventCode IN (4723, 4724)
| bin _time span=10m
| stats dc(host) as value_count by _time TargetSid
| search value_count >= 10
```

</details>

<details>

<summary>User password change using current hash password - ChangeNTLM (Mimikatz)</summary>

```yaml
title: User password change using current hash password - ChangeNTLM (Mimikatz)
description: Detects scenarios where an attacker resets a user account by using the compromised NTLM password hash. The newly clear text password defined by the attacker can be then used in order to login into services like Outlook Web Access (OWA), RDP, SharePoint... As ID 4723 refers to user changing is own password, the SubjectSid and TargetSid should be equal. However in a change initiated by Mimikatz, they will be different. Correlate the event ID 4723, 4624 and 5145 using the "SubjectLogonId" field to identify the source of the reset.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
  - https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/
  - https://www.trustedsec.com/blog/azure-account-hijacking-using-mimikatzs-lsadumpsetntlm/
  - https://www.trustedsec.com/blog/manipulating-user-passwords-without-mimikatz/
tags:
  - attack.persistence
  - attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4723 # Self password reset
    TargetSid|startswith: S-1-5-21-
    SubjectUserSid|startswith: S-1-5-21-
    #SubjectUserSid != TargetSid # comparing 2 fields is not possible in SIGMA language
  condition: selection
falsepositives:
  - Admin changing is own account directly using the Active Directory console and not the GUI (ctrl alt suppr)
  - ADFS, MSOL, DirSync, Azure AD Sync
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4723 TargetSid="S-1-5-21-*" SubjectUserSid="S-1-5-21-*"
```
{% endcode %}

</details>

<details>

<summary>Suspicious Kerberos password account reset to issue potential Golden ticket</summary>

```yaml
title: Suspicious Kerberos password account reset to issue potential Golden ticket
description: Detects scenarios where a suspicious password reset of the Krbtgt account is performed by attacker to issue a potential Golden ticket.
references:
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf
- https://adsecurity.org/?p=483
tags:
- attack.credential_access
- attack.t1558.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4724
    TargetSid|endswith: '-502' # Krbtgt account SID
  condition: selection
falsepositives:
- Administrators following best practices and reseting the Krbtgt password 1 or 2 times a year
level: medium
```

```splunk-spl
source="WinEventLog:Security" EventCode=4724 TargetSid="*-502"
```

</details>

<details>

<summary>Remote domain controller password reset (Zerologon)</summary>

```yaml
title: Remote domain controller password reset (Zerologon) 
description: Detects scenarios where an attacker attempts to exploit the Zerologon vulnerabiliy which triggers, bsides others things, a password reset on a domain controller.
references:
- https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
- https://stealthbits.com/blog/zerologon-from-zero-to-hero-part-2/
- https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/
- https://blog.nviso.eu/2020/09/17/sentinel-query-detect-zerologon-cve-2020-1472/
- https://blog.zsec.uk/zerologon-attacking-defending/
tags:
- attack.lateral_movement
- attack.t1210 # Exploitation of Remote Services 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  domain_controller:
    Computer: '%domain_controllers%'

  selection_account_changed:
    EventID: 4742 # computer account changed
    TargetUserName|endswith: '$' # focus only on computer accounts

  filter_account_changed:
    PasswordLastSet: '-'
  
  selection_reset:
    EventID: 4724

  condition: domain_controller and (selection_reset or (selection_account_changed and not filter_account_changed) )
falsepositives:
- None 
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" Computer="%domain_controllers%" EventCode=4724 OR (EventCode=4742 TargetUserName="*$" NOT PasswordLastSet="-")
```
{% endcode %}

</details>

<details>

<summary>User password change without previous password known - SetNTLM (Mimikatz)</summary>

```yaml
title: User password change without previous password known - SetNTLM (Mimikatz)
description: Detects scenarios where an attacker perform a password reset event. This does not require any knowledge of a user’s current password, but it does require to have the "Reset Password" right. Correlate the event ID 4724, 4624 and 5145 using the "SubjectLogonId" field to identify the source of the reset.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
  - https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/
  - https://www.trustedsec.com/blog/azure-account-hijacking-using-mimikatzs-lsadumpsetntlm/
  - https://www.trustedsec.com/blog/manipulating-user-passwords-without-mimikatz/
tags:
  - attack.persistence
  - attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_reset:
    EventID: 4724 # Non self password reset
    TargetSid|startswith: S-1-5-21-
    SubjectUserSid|startswith: S-1-5-21-

  selection_share:
    EventID: 5145
    ShareName: \\*\IPC$
    RelativeTargetName: samr

  selection_login:
    EventID: 4624
    AuthenticationPackageName: NTLM

  filter:
    IpAddress:
      - "127.0.0.1"
      - "::1"

  condition: (selection_reset and selection_share and selection_login) and not filter
falsepositives:
  - None
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode=4724 TargetSid="S-1-5-21-*" SubjectUserSid="S-1-5-21-*" EventCode=5145 ShareName="\\*\\IPC$" RelativeTargetName="samr" EventCode=4624 AuthenticationPackageName="NTLM" NOT (IpAddress IN ("127.0.0.1", "::1"))
```
{% endcode %}

</details>

***

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724)
3. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865\(v=ws.11\))
4. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2022-ps)

***
