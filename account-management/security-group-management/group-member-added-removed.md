# Group Member Added/Removed

### Event Description

* **Event ID 4728**: This event is logged when a user is added to a security-enabled global group. It includes details about the target account and the group modified. Monitoring this event is essential for tracking group membership changes that could indicate privilege escalation.
* **Event ID 4729**: This event is generated when a user is removed from a security-enabled global group. It helps in monitoring any potential reduction in group privileges.
* **Event ID 4732**: This event is logged when a user is added to a security-enabled local group. Tracking this event is important to detect any unauthorized privilege elevation on local groups.
* **Event ID 4733**: This event is generated when a user is removed from a security-enabled local group. It helps monitor any administrative adjustments to local group memberships.
* **Event ID 4756**: This event occurs when a user is added to a security-enabled universal group. This is important for tracking changes across domains in multi-domain environments.
* **Event ID 4757**: This event is generated when a user is removed from a security-enabled universal group, providing insights into group membership modifications.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Simulating User Addition to a Group**:
  * Log in to a domain controller with administrative privileges.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Locate the target group, right-click, and select **Add to Group**.
  * Choose a user to add to the group.
  * Check **Event Viewer** to confirm the appropriate event is logged (e.g., **Event ID 4728** or **4732**, depending on the group type).
* **Simulating User Removal from a Group**:
  * In **ADUC**, go to the desired group.
  * Right-click the user and select **Remove from Group**.
  * Confirm that **Event Viewer** logs the corresponding event (e.g., **Event ID 4729** or **4733**).
* **Verification for Universal Groups**:
  * For universal groups, repeat the above steps and check for **Event IDs 4756** and **4757**.
{% endtab %}

{% tab title="CMD" %}
```batch
:: Add user to group
net group <group_name_in_string> <username> /add
:: Remove user to group
net group <group_name_in_string> <username> /delete
```
{% endtab %}

{% tab title="Powershell" %}
```powershell
# Add user to group
Add-ADGroupMember -Identity "Backup Operators" -Members "testuser"
# Remove the user from the group
Remove-ADGroupMember -Identity "Backup Operators" -Members "testuser"
```
{% endtab %}
{% endtabs %}

For this example, we took a security-enabled local group. The commands are the same for all other groups like global groups and universal groups.

***

### Event Viewer Logs

> Audit Success 14-11-2024 11:10:32 Microsoft Windows security auditing. 4732 Security Group Management \
> Audit Success 14-11-2024 15:06:34 Microsoft Windows security auditing. 4733 Security Group Management

For this example, we took a security-enabled local group. The logs are the same for all other groups like global groups and universal groups but with different Event Code.

***

### Splunk Queries

The below query will find any users that were added to any security-enabled groups.

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(4728,4729,4732,4733,4756,4757)
|stats values(Subject_Account_Name) as Subject_Account_Name values(Group_Security_ID) as group_name_id values(Member_Security_ID) as user_id values(ComputerName) as ComputerName values(action) as action values(status) as status count by index sourcetype host EventCode signature Group_Name src_user user
```
{% endcode %}

***

### Splunk Logs

{% tabs %}
{% tab title="Member Added" %}
```
11/14/2024 11:10:32 AM
LogName=Security
EventCode=4732
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=36267
Keywords=Audit Success
TaskCategory=Security Group Management
OpCode=Info
Message=A member was added to a security-enabled local group.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0x81195

Member:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1108
	Account Name:		CN=testuser,CN=Users,DC=test,DC=com

Group:
	Security ID:		S-1-5-32-551
	Group Name:		Backup Operators
	Group Domain:		Builtin

Additional Information:
	Privileges:		-
```

For this example, we took a security-enabled local group called **Backup Operators.**
{% endtab %}

{% tab title="Member Removed" %}
```
11/14/2024 03:06:34 PM
LogName=Security
EventCode=4733
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=41853
Keywords=Audit Success
TaskCategory=Security Group Management
OpCode=Info
Message=A member was removed from a security-enabled local group.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x2EA05B

Member:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1108
	Account Name:		CN=testuser,CN=Users,DC=test,DC=com

Group:
	Security ID:		S-1-5-32-551
	Group Name:		Backup Operators
	Group Domain:		Builtin

Additional Information:
	Privileges:		-
```

For this example, we took a security-enabled local group called **Backup Operators.**
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>High risk Active Directory group membership change</summary>

```yaml
title: High risk Active Directory group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      #- 4732 # local and domain local group are covered in another rule
    TargetSid|startswith: 'S-1-5-21-'
    TargetSid|endswith:
      - '-512' # Domain Admins (global)
      - '-518' # Schema Admins (universal)
      - '-519' # Enterprise Admins (universal)
      - '-520' # Group Policy Creator Owners (global)
      #- '-525' # Protected users (global) > focus only on removal actions, not adding . See dedicated rule
      - '-526' # Key Admins (global)
      - '-527' # Enterprise Key Admins (universal)
  condition: selection
falsepositives:
- Administrator activity
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756") AND TargetSid="S-1-5-21-*" AND (TargetSid="*-512" OR TargetSid="*-518" OR TargetSid="*-519" OR TargetSid="*-520" OR TargetSid="*-526" OR TargetSid="*-527"))
```
{% endcode %}

</details>

<details>

<summary>Medium risk Active Directory group membership change</summary>

```yaml
title: Medium risk Active Directory group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      #- 4732 # local and domain local group are covered in another rule
    TargetSid|startswith: 'S-1-5-21-'
    TargetSid|endswith:
      - '-514' # Domain Guests
      - '-517' # Cert Publishers
      - '-520' # Group Policy Creator Owners
  condition: selection
falsepositives:
- Administrator activity
level: medium
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756") AND TargetSid="S-1-5-21-*" AND (TargetSid="*-514" OR TargetSid="*-517" OR TargetSid="*-520"))
```
{% endcode %}

</details>

<details>

<summary>Massive group membership changes detected</summary>

```yaml
title: Massive group membership changes detected
name: massive_group_changes
description: Detects scenarios where an attacker will add a compromised account into different domain groups in order to gain access to all the assets under the control of those concerned groups.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
  condition: selection
falsepositives:
  - Automatic scripts, provisionning accounts
level: medium

---
title: Massive group membership changes detected Count
status: experimental
correlation:
  type: value_count
  rules:
    - massive_group_changes # Referenced here
  group-by:
    - SubjectUserSid
  timespan: 15m
  condition:
    gte: 20
    field: TargetSid # Count how many different groups had a member added in a short period by the same user
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source="WinEventLog:Security" EventCode IN (4728, 4756, 4732)
| bin _time span=15m
| stats dc(TargetSid) as value_count by _time SubjectUserSid
| search value_count >= 20
```
{% endcode %}

</details>

<details>

<summary>Member added to DNSadmin group</summary>

```yaml
title: Member added to DNSadmin group
description: Detects scenarios where a suspicious change is done on DNSadmin group in order to abuse DNSadmin privileges for DLL load.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html
- https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
- http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html
- https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
- https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b
- https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2
- https://phackt.com/dnsadmins-group-exploitation-write-permissions
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added > group below is per default with this group type
    TargetUserName: DnsAdmins # Group SID is random
  condition: selection
falsepositives:
- Rare administrator activity
level: high

```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND TargetUserName="DnsAdmins")
```
{% endcode %}

</details>

<details>

<summary>Exchange group membership change to perform DCsync attack</summary>

```yaml
title: Exchange group membership change to perform DCsync attack
description: Detects scenarios where an attacker adds its account into a sensitive Exchange group to obtain "Replicating Directory Changes /all" and perform DCsync attack.
references:
- https://adsecurity.org/?p=4119
- https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access
- https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
tags:
- attack.credential_access
- attack.t1003.006
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added > groups below are per default with this group type
      - 4732 # local and domain local group member added
    TargetUserName:
      - 'Exchange Trusted Subsystem'
      - 'Exchange Windows Permissions'
  condition: selection
falsepositives:
- Exchange administrator updating server configuration
- Exchange upgrade or migration
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="Exchange Trusted Subsystem" OR TargetUserName="Exchange Windows Permissions"))
```
{% endcode %}

</details>

<details>

<summary>New member added to an Exchange administration group (high risk)</summary>

```yaml
title: New member added to an Exchange administration group (high risk)
description: Detects scenarios where a new member is added to a sensitive group related to Exchange server
references:
- https://msexchangeguru.com/2015/12/18/rbac-2016/
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
    TargetUserName:
      #- 'Exchange Trusted Subsystem' > See related rule for DC sync group change
      #- 'Exchange Windows Permissions' > See related rule for DC sync group change
      - 'Exchange Organization Administrators'
      - 'Exchange Public Folder Administrators'
      - 'Exchange Recipient Administrators'
      - 'Security Administrator'
      - 'Exchange Domain Servers'
      - 'Exchange Enterprise Servers'
      - 'Exchange Servers'
  condition: selection
falsepositives:
- Exchange administrator updating server configuration
- Exchange upgrade or migration
level: medium
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="Exchange Organization Administrators" OR TargetUserName="Exchange Public Folder Administrators" OR TargetUserName="Exchange Recipient Administrators" OR TargetUserName="Security Administrator" OR TargetUserName="Exchange Domain Servers" OR TargetUserName="Exchange Enterprise Servers" OR TargetUserName="Exchange Servers"))
```
{% endcode %}

</details>

<details>

<summary>New member added to an Exchange administration group (medium risk)</summary>

```yaml
title: New member added to an Exchange administration group (medium risk)
description: Detects scenarios where a new member is added to a sensitive group related to Exchange server
references:
- https://msexchangeguru.com/2015/12/18/rbac-2016/
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
    TargetUserName:
      - 'Security Reader'
      - 'Exchange View-Only Administrators'
      - 'Organization Management'
      - 'Public Folder Management'
      - 'Recipient Management'
      - 'Records Management'
      - 'Server Management'
      - 'UM Management'
      - 'View-only Organization Management'
  condition: selection
falsepositives:
- Exchange administrator updating server configuration
- Exchange upgrade or migration
level: medium
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="Security Reader" OR TargetUserName="Exchange View-Only Administrators" OR TargetUserName="Organization Management" OR TargetUserName="Public Folder Management" OR TargetUserName="Recipient Management" OR TargetUserName="Records Management" OR TargetUserName="Server Management" OR TargetUserName="UM Management" OR TargetUserName="View-only Organization Management"))
```
{% endcode %}

</details>

<details>

<summary>New member added to an "OCS/Lync/Skype for Business" administration group (high risk)</summary>

```yaml
title: New member added to an "OCS/Lync/Skype for Business" administration group (high risk)
description: Detects scenarios where a new member is added to a sensitive administration group related to OCS/Lync/Skype for Business in order to scan topology, infiltrate servers and move laterally.
references:
- https://docs.microsoft.com/en-us/previous-versions/office/lync-server-2013/lync-server-2013-planning-for-role-based-access-control
- https://docs.microsoft.com/en-us/skypeforbusiness/schema-reference/active-directory-schema-extensions-classes-and-attributes/changes-made-by-forest-preparation
- https://blog.insideo365.com/2012/11/a-lync-administrator-access-refresher/
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
    TargetUserName:
      - CSAdministrator
      - CSServerAdministrator
      - RTCUniversalServerAdmins
  condition: selection
falsepositives:
- OCS/Lync/Skype administrator updating server configuration or topology
- OCS/Lync/Skype upgrade or migration
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="CSAdministrator" OR TargetUserName="CSServerAdministrator" OR TargetUserName="RTCUniversalServerAdmins"))
```
{% endcode %}

</details>

<details>

<summary>New member added to a "OCS/Lync/Skype for Business" administration group (low risk)</summary>

```yaml
title: New member added to a "OCS/Lync/Skype for Business" administration group (low risk)
description: Detects scenarios where a new member is added to a sensitive administration group related to OCS/Lync/Skype for Business in order to scan topology, infiltrate servers and move laterally.
references:
- https://docs.microsoft.com/en-us/previous-versions/office/lync-server-2013/lync-server-2013-planning-for-role-based-access-control
- https://docs.microsoft.com/en-us/skypeforbusiness/schema-reference/active-directory-schema-extensions-classes-and-attributes/changes-made-by-forest-preparation
- https://blog.insideo365.com/2012/11/a-lync-administrator-access-refresher/
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
    TargetUserName:
      - CSHelpDesk
      - CSLocationAdministrator
      - CSPersistentChatAdministrator
      - CSResponseGroupAdministrator
      - CSResponseGroupManager
      - CSViewOnlyAdministrator
      - CSVoiceAdministrator
      - RTCComponentUniversalServices
      - RTCProxyUniversalServices
      - RTCSBAUniversalServices
      - RTCUniversalConfigReplicator
      - RTCUniversalGlobalReadOnlyGroup
      - RTCUniversalReadOnlyAdmins
      - RTCUniversalServerReadOnlyGroup
      - RTCUniversalUserAdmins
      - RTCUniversalUserReadOnlyGroup
  condition: selection
falsepositives:
- OCS/Lync/Skype administrator updating server configuration or topology
- OCS/Lync/Skype upgrade or migration
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="CSHelpDesk" OR TargetUserName="CSLocationAdministrator" OR TargetUserName="CSPersistentChatAdministrator" OR TargetUserName="CSResponseGroupAdministrator" OR TargetUserName="CSResponseGroupManager" OR TargetUserName="CSViewOnlyAdministrator" OR TargetUserName="CSVoiceAdministrator" OR TargetUserName="RTCComponentUniversalServices" OR TargetUserName="RTCProxyUniversalServices" OR TargetUserName="RTCSBAUniversalServices" OR TargetUserName="RTCUniversalConfigReplicator" OR TargetUserName="RTCUniversalGlobalReadOnlyGroup" OR TargetUserName="RTCUniversalReadOnlyAdmins" OR TargetUserName="RTCUniversalServerReadOnlyGroup" OR TargetUserName="RTCUniversalUserAdmins" OR TargetUserName="RTCUniversalUserReadOnlyGroup"))
```
{% endcode %}

</details>

<details>

<summary>New member added to a "OCS/Lync/Skype for Business" administration group (medium risk)</summary>

```yaml
title: New member added to a "OCS/Lync/Skype for Business" administration group (medium risk)
description: Detects scenarios where a new member is added to a sensitive administration group related to OCS/Lync/Skype for Business in order to scan topology, infiltrate servers and move laterally.
references:
- https://docs.microsoft.com/en-us/previous-versions/office/lync-server-2013/lync-server-2013-planning-for-role-based-access-control
- https://docs.microsoft.com/en-us/skypeforbusiness/schema-reference/active-directory-schema-extensions-classes-and-attributes/changes-made-by-forest-preparation
- https://blog.insideo365.com/2012/11/a-lync-administrator-access-refresher/
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
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
    TargetUserName:
      - CSArchivingAdministrator
      - CSUserAdministrator
      - RTCHSUniversalServices
      - RTCUniversalGlobalWriteGroup
      - RTCUniversalSBATechnicians
  condition: selection
falsepositives:
- OCS/Lync/Skype administrator updating server configuration or topology
- OCS/Lync/Skype upgrade or migration
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND ((EventID="4728" OR EventID="4756" OR EventID="4732") AND (TargetUserName="CSArchivingAdministrator" OR TargetUserName="CSUserAdministrator" OR TargetUserName="RTCHSUniversalServices" OR TargetUserName="RTCUniversalGlobalWriteGroup" OR TargetUserName="RTCUniversalSBATechnicians"))
```
{% endcode %}

</details>

<details>

<summary>High risk local/domain local group membership change</summary>

```yaml
title: High risk local/domain local group membership change
description: Detects scenarios where a suspicious group membership is changed. Having Microsoft LAPS installed may trigger false positive events for the builtin administrators group triggered by the system account (S-1-5-18).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
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
    EventID: 4732 # local and domain local group
    TargetSid|startswith: 'S-1-5-32'
    TargetSid|endswith:
      - '-544' # Administrators
      - '-547' # Power Users
      - '-548' # Account Operators
      - '-549' # Server Operators
      - '-551' # Backup Operators
      - '-578' # Hyper-V Administrators
  filter:
    SubjectUserSid: 'S-1-5-18' # LAPS or others IAM solutions may trigger this as a false positive
  condition: selection and not filter
falsepositives:
- Administrator activity
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4732" AND TargetSid="S-1-5-32*" AND (TargetSid="*-544" OR TargetSid="*-547" OR TargetSid="*-548" OR TargetSid="*-549" OR TargetSid="*-551" OR TargetSid="*-578")) AND  NOT (SubjectUserSid="S-1-5-18")
```
{% endcode %}

</details>

<details>

<summary>Medium risk local/domain local group membership change</summary>

```yaml
title: Medium risk local/domain local group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
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
    EventID: 4732 # local and domain local group
    TargetSid|startswith: 'S-1-5-32'
    TargetSid|endswith:
      - '-546'  # Guests
      - '-550'  # Print Operators
      - '-555'  # Remote Desktop Users
      - '-556'  # Network Configuration Operators
      - '-557'  # Incoming Forest Trust Builders
      - '-560'  # Windows Authorization Access Group
      - '-562'  # Distributed COM Users
      - '-568'  # IIS_IUSRS
      - '-569'  # Cryptographic Operators
      - '-573'  # Event Log Readers
      - '-574'  # Certificate Service DCOM Access
      - '-579'  # Access Control Assistance Operators
      - '-580'  # Remote Management Users
      - '-582'  # Storage Replica Administrators
      # add DnsAdmins group but has no default RID
  filter_sytem:
    SubjectUserSid: 'S-1-5-18' # LAPS or others IAM solutions may trigger this as a false positive
  filter_iis:
    TargetSid: "S-1-5-32-568" # IIS_IUSRS
    MemberSid: "S-1-5-20"     # Network service account
  condition: selection and not (filter_sytem OR filter_iis)
falsepositives:
- Administrator activity
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4732" AND TargetSid="S-1-5-32*" AND (TargetSid="*-546" OR TargetSid="*-550" OR TargetSid="*-555" OR TargetSid="*-556" OR TargetSid="*-557" OR TargetSid="*-560" OR TargetSid="*-562" OR TargetSid="*-568" OR TargetSid="*-569" OR TargetSid="*-573" OR TargetSid="*-574" OR TargetSid="*-579" OR TargetSid="*-580" OR TargetSid="*-582")) AND  NOT (SubjectUserSid="S-1-5-18" OR (TargetSid="S-1-5-32-568" AND MemberSid="S-1-5-20"))
```
{% endcode %}

</details>

***

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051\(v=ws.11\))
2. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2022-ps)
3. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember?view=windowsserver2022-ps)
4. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)

***
