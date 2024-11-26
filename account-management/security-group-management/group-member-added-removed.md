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

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### Sigma Rules



***

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051\(v=ws.11\))
2. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2022-ps)
3. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember?view=windowsserver2022-ps)
4. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)

***
