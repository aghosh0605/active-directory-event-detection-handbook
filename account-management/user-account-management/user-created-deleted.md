# User Created/Deleted

### Event Description

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

***

### References

1. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865\(v=ws.11\))
3. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2022-ps)
4. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
5. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726)
