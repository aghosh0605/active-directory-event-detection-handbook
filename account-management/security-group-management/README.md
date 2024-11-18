# Security Group Management

When modifying a group description in Active Directory, the change may not capture the exact details (like the updated description) in the logs by default. Instead, you’ll see a general "Group modified" entry in the Security logs. This event indicates that an object was modified but does not provide specifics about the attributes that were changed.

We will take an example as **Group Description Change** and will try to collect the logs in which the value of Group Description will be available.

### Turn on Group Policies

<details>

<summary>Enable "Audit Directory Service Changes" Policy</summary>

* Open **Group Policy Management Console (GPMC)**.
* Create or edit a Group Policy Object (GPO) that applies to the relevant domain controllers.
*   Navigate to:

    ```
    Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > DS Access
    ```
* Double-click **Audit Directory Service Changes**, then:
  * Check **Configure the following audit events**.
  * Enable both **Success** and **Failure** as required.
* Apply and save the changes.

</details>

After turning this on, we need to explicitly enable auditing on the specific group or groups in AD where you want detailed logs.

<details>

<summary>Enable Auditing on the Group Object in Active Directory</summary>

* **Open Active Directory Users and Computers (ADUC)**:
  * Run `dsa.msc`.
* **Enable Advanced Features**:
  * In the **View** menu, enable **Advanced Features**.
* **Access the Group’s Security Settings**:
  * Locate the group whose description changes you want to monitor.
  * Right-click the group > **Properties** > **Security** tab > **Advanced** > **Auditing** tab.
* **Add an Auditing Entry**:
  * Click **Add** > **Principal**: Select `Everyone` or a specific user/group to monitor.
  * **Type**: Set to **Success**.
  * **Applies to**: Select **This object.**
  * **Permissions**: Check **Write all properties** or specifically **Write Description**.
* Save the setting

</details>

Once configured, any changes to the group, including its description, will generate detailed logs like below. For us, we will be changing the group description and checking the logs for it.

```
11/18/2024 11:24:31 AM
LogName=Security
EventCode=5136
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=55492
Keywords=Audit Success
TaskCategory=Directory Service Changes
OpCode=Info
Message=A directory service object was modified.
	
Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		Administrator
	Account Domain:		TEST
	Logon ID:		0x44E7F

Directory Service:
	Name:	test.com
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=splunk,OU=Users,OU=Blue,DC=test,DC=com
	GUID:	{755f2ae9-3b6f-44d1-a413-b1b8d04ed014}
	Class:	group
	
Attribute:
	LDAP Display Name:	description
	Syntax (OID):	2.5.5.12
	Value:	Changed Splunk Group
	
Operation:
	Type:	Value Added
	Correlation ID:	{06e3ab5f-957b-4fb8-8f91-bcafdd3d21ba}
	Application Correlation ID:	-
```

Under Attribute, the value key shows the changed group description of the group we selected for audit.
