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

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

### Sigma Rules

<details>

<summary></summary>



</details>



***

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724)
3. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865\(v=ws.11\))
4. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2022-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2022-ps)

***
