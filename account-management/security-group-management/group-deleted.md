# Group Deleted

### Event Description

* **Event ID 4730**: This event is generated when a security-enabled global group is deleted. It includes details about the deleted group and the user initiating the action. Tracking global group deletions is essential to ensure critical domain-level groups are not removed without authorization.
* **Event ID 4734**: This event is logged when a security-enabled local group is deleted. It captures information about the group that was deleted and the account responsible for the action. Monitoring this event is critical for detecting unauthorized deletions of local groups.
* **Event ID 4758**: This event is triggered when a security-enabled universal group is deleted. As universal groups often have cross-domain implications, monitoring their deletion is vital to maintain security and prevent accidental or malicious disruptions to access control.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Simulating Local Group Deletion**:
  * Log in with administrative privileges on a system where local groups can be managed.
  * Open **Computer Management** and navigate to **Local Users and Groups**.
  * Delete a security-enabled local group.
  * Verify that **Event ID 4734** is logged in **Event Viewer** > **Windows Logs** > **Security**.
* **Simulating Global Group Deletion**:
  * Log in to a domain controller or a system with Active Directory management privileges.
  * Open **Active Directory Users and Computers (ADUC)**.
  * Locate a security-enabled global group and delete it.
  * Confirm that **Event ID 4730** is generated and recorded in **Event Viewer**.
* **Simulating Universal Group Deletion**:
  * In **ADUC**, find a security-enabled universal group and delete it.
  * Check **Event Viewer** for **Event ID 4758** to confirm the action was logged.
{% endtab %}

{% tab title="CMD" %}
```batch
:: Delete a group
net group /delete /domain "groupname"
```
{% endtab %}

{% tab title="Powershell" %}
```powershell
# Delete a group
Remove-ADGroup -Identity "groupname"
```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 18-11-2024 14:48:40 Microsoft Windows security auditing. 4730 Security Group Management

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(4734,4730,4758)
|stats values(Subject_Account_Name) as Subject_Account_Name values(Group_Security_ID) as groupame values(Member_Security_ID) as user_id values(ComputerName) as ComputerName values(action) as action values(status) as status count by index sourcetype host EventCode signature Group_Name src_user
```
{% endcode %}

***

### Splunk Logs

```
11/18/2024 02:48:40 PM
LogName=Security
EventCode=4730
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=60339
Keywords=Audit Success
TaskCategory=Security Group Management
OpCode=Info
Message=A security-enabled global group was deleted.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x44E7F

Deleted Group:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1109
	Group Name:		splunk
	Group Domain:		TEST

Additional Information:
	Privileges:		-
```

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)
2. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroup?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroup?view=windowsserver2022-ps)
3. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051\(v=ws.11\))

***
