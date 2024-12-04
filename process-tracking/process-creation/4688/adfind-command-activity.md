# AdFind Command Activity

### Description

AdFind.exe is a command line Active Directory query tool. Mixture of ldapsearch, search.vbs, ldp, dsquery, and dsget tools with a ton of other cool features thrown in for good measure. This tool proceeded dsquery/dsget/etc by years though I did adopt some of the useful stuff from those tools.

### Use Case Implementation

1. Download the AdFind tool from the link [here](https://www.joeware.net/freetools/tools/adfind/).&#x20;
2. Run the following command to get all the users in the Active Directory Environment.

```batch
adfind -b "DC=test,DC=com" -f "(&(objectCategory=person)(objectClass=user))"
```

For example, we took the domain as test.com

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode=4688 process_name="AdFind.exe" user!=*$
| table index host sourcetype TaskCategory dvc user name EventCode action process_name
| dedup user
```
{% endcode %}

### Splunk Log

```
12/04/2024 11:59:18 AM
LogName=Security
EventCode=4688
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=136537
Keywords=Audit Success
TaskCategory=Process Creation
OpCode=Info
Message=A new process has been created.

Creator Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x41E76

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x1394
	New Process Name:	C:\Users\Administrator\Downloads\AdFind\AdFind.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0x1460
	Creator Process Name:	C:\Windows\System32\cmd.exe
	Process Command Line:	AdFind.exe  "DC=test,DC=com" -f "(&(objectCategory=person)(objectClass=user))"
```

### Splunk Alert

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>
