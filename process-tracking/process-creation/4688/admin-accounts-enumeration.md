# Admin Accounts Enumeration

### Description

The administrator accounts have the highest privileges and are therefore of the most value to attackers. Knowing the queries to find these accounts helps defenders detect this kind of discovery activity in their networks.

### Use Case Implementation

The below command for example can be used to get the "Domain Admins" in an Active Directory Environment.

```batch
net group /domain "domain admins"
```

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode=4688 Account_Name!=*$ user!=*$ process_name IN ("net.exe","net1.exe") _raw IN ("*Domain Admins*", "*Remote Desktop Users*", "*Enterprise Admins*", "*Organization Management*", "*Backup Operators*", "*DNSAdmins*")
| stats count values(user) as user values(TaskCategory) as TaskCategory values(EventCode) as EventCode values(action) as action values(name) as name values(process_name) as process_name by index host sourcetype dvc Account_Name
```
{% endcode %}

### Splunk Log

```
12/05/2024 02:22:47 PM
LogName=Security
EventCode=4688
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=150389
Keywords=Audit Success
TaskCategory=Process Creation
OpCode=Info
Message=A new process has been created.

Creator Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x3C3F54

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x16f8
	New Process Name:	C:\Windows\System32\net1.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0xf1c
	Creator Process Name:	C:\Windows\System32\net.exe
	Process Command Line:	C:\Windows\system32\net1  group  /domain "domain admins"
```

### Splunk Alert

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>
