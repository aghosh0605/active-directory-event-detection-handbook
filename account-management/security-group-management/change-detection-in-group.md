# Change Detection in Group

### Event Description

* **Event ID 4735**: This event is logged when a security-enabled local group is modified. It includes details of the modified group, the user making the change, and what changes were made. Monitoring this event is useful for tracking modifications to local groups, which could indicate privilege escalation or unauthorized changes.
* **Event ID 4737**: This event is generated when a security-enabled global group is modified. Similar to Event ID 4735, it captures details about the group modifications but focuses on global groups. Monitoring global group changes can help detect unauthorized access adjustments, especially in domain environments.
* **Event ID 4755**: This event occurs when a security-enabled universal group is modified. Universal groups often span multiple domains, so changes here can impact access across a broader scope. Tracking Event ID 4755 helps monitor significant group membership or permission changes that may affect multiple domains.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Simulating Local Group Modification**:
  * Log in with administrative privileges on a system with access to local group management.
  * Open **Computer Management** and navigate to **Local Users and Groups**.
  * Modify a security-enabled local group by adding or removing a member, or by changing group properties.
  * Confirm **Event ID 4735** is logged in **Event Viewer** > **Windows Logs** > **Security**.
* **Simulating Global Group Modification**:
  * Log in to a domain controller or a system with access to manage Active Directory groups.
  * In **Active Directory Users and Computers (ADUC)**, locate and modify a security-enabled global group by adding or removing members.
  * Check **Event Viewer** to verify that **Event ID 4737** is recorded.
* **Simulating Universal Group Modification**:
  * In **ADUC**, locate a security-enabled universal group and perform a modification, such as changing members.
  * Confirm **Event ID 4755** is generated for this action in **Event Viewer**.
{% endtab %}

{% tab title="CMD" %}
```batch
:: Change group description
net group "GroupName" /comment:"New Group Description" /domain
```
{% endtab %}

{% tab title="Powershell" %}
```powershell
# Change group description
Set-ADGroup -Identity "GroupName" -Description "New Group Description"
```
{% endtab %}
{% endtabs %}

For this example, we took a security-enabled local group. The commands are the same for all other groups like global groups and universal groups.

***

### Event Viewer Logs

> Audit Success 15-11-2024 12:09:18 Microsoft Windows security auditing. 4735 Security Group Management\
> Audit Success 15-11-2024 12:09:18 Microsoft Windows security auditing. 4737 Security Group Management\
> Audit Success 15-11-2024 12:09:18 Microsoft Windows security auditing. 4755 Security Group Management

***

### Splunk Queries

The command below can be used to detect any changes in any security-enabled groups.

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(4735,4737,4755) 
|stats values(Group_Security_ID) as Group_Security_ID,values(Subject_Security_ID) as Subect_Security_ID,values(Message) as Message,values(Security_ID) as Security_ID count by index sourcetype host ComputerName action EventCode Group_Name status src_user
```
{% endcode %}

***

### Splunk Logs

```
11/18/2024 10:48:49 AM
LogName=Security
EventCode=4737
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=54599
Keywords=Audit Success
TaskCategory=Security Group Management
OpCode=Info
Message=A security-enabled global group was changed.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x44E7F

Group:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1109
	Group Name:		splunk
	Group Domain:		TEST

Changed Attributes:
	SAM Account Name:	-
	SID History:		-

Additional Information:
	Privileges:		-
```

{% hint style="warning" %}
This Event ID only indicates that the group has been changed. However, the respective Event IDs provide information about the changes made. So, it's better not to fully rely upon this Event ID.  \
For example, if any members are added to the group the respective event IDs like 4728,4729,4732,4733,4756,4757 will show the specific logs for it.
{% endhint %}

To get more detailed info about what changed in the group. Please enable the required group policies mentioned [here](./) accordingly.&#x20;

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

<details>

<summary>SearchIndexer suspicious process activity</summary>

```yaml
title: SearchIndexer suspicious process activity
description: Detects scenarios where SearchIndexer spwaned another process with the same name, or when SearchIndexer process exists in an unexpected directory.
references:
- https://securityaffairs.co/wordpress/75782/cyber-crime/hacking-hacker-botnet.html
- https://www.joesandbox.com/analysis/213580/1/html
- https://www.virustotal.com/gui/file/eb8417d0cf40160474faf587f3e1fdf94a0a2c9636ad1cf32005ff29ef3852dc
- https://www.filescan.io/uploads/62ad24c8473553ed319b5fe3/reports/104d3e08-1bdb-43ce-beb8-07c5688cef03/details
- https://any.run/report/eb8417d0cf40160474faf587f3e1fdf94a0a2c9636ad1cf32005ff29ef3852dc/c323438a-a3ec-4dcc-b304-dc47882a1eab
tags:
- attack.defense_evasion
- attack.t1036 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection:

  selection_parent_image:
    ParentImage|endswith: '\SearchIndexer.exe' 

  selection_image:
    Image|endswith: '\SearchIndexer.exe'

  selection_image_path:
    Image: 'C:\WINDOWS\system32\SearchIndexer.exe'

  selection_commandline:
    CommandLine|contains: 'c1 c2 c3 c4 c5 c6 c7 c8'

  condition: (selection_parent_image and selection_image) or (selection_image and not selection_image_path) or (selection_image and selection_commandline)
falsepositives:
- None 
level: medium
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (ParentImage="*\\SearchIndexer.exe" AND Image="*\\SearchIndexer.exe") OR (Image="*\\SearchIndexer.exe" AND  NOT (Image="C:\\WINDOWS\\system32\\SearchIndexer.exe")) OR (Image="*\\SearchIndexer.exe" AND CommandLine="*c1 c2 c3 c4 c5 c6 c7 c8*")
```
{% endcode %}

</details>

### References

1. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adgroup?view=windowsserver2022-ps#description](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adgroup?view=windowsserver2022-ps#description)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4735](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4735)
3. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)

***
