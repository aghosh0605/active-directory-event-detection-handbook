# Red Team Tools Detect

### Description

This usecase helps to detect tools used by red team experts or an hacker by a list of names available in an CSV file. Lookup is used to detect with the processname.\
An example of the CSV file is attached with this docs.  Get it below.

{% file src="../../../.gitbook/assets/Process_Name.csv" %}
Example CSV File
{% endfile %}

### Use Case Implementation&#x20;

Download red team tools like [**SharpHound.exe** ](https://github.com/BloodHoundAD/SharpHound/releases)or [**Mimikatz.exe**](https://github.com/ParrotSec/mimikatz/blob/master/Win32/mimikatz.exe) from Githu&#x62;**.** Execute those in CMD. Below are the commands used to execute.

```batch
:: Run in SharpHound Directory
SharpHound.exe --collectionmethods All --ZipFileName output.zip
:: Run in Mimikatz Directory
mimikatz.exe "lsadump::lsa /inject" exit
```

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode=4688
| rename new_process_name as Process_Name
| stats values(matched) as process_started count by index host sourcetype EventCode signature user process_path New_Process_Name Process_Name
| lookup Process_Name Process_Name OUTPUT Process_Name as matched
| search matched=*
```
{% endcode %}

{% hint style="warning" %}
The CSV file needs to be uploaded to the lookups in Splunk Server. Also, **Lookup definitions** is needed for not using the case-sensitive search. \
You can check the [references](red-team-tools-detect.md#references) section to get more idea from the blogs that are atatched there.
{% endhint %}

### Splunk Log

{% tabs %}
{% tab title="SharpHound" %}
```
12/04/2024 02:49:29 PM
LogName=Security
EventCode=4688
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=138832
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
	New Process ID:		0x1b6c
	New Process Name:	C:\Users\Administrator\Downloads\SharpHound-v2.5.9\SharpHound.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0x13fc
	Creator Process Name:	C:\Windows\System32\cmd.exe
	Process Command Line:	SharpHound.exe  --collectionmethods All -ZipFileName output.zip
```
{% endtab %}

{% tab title="Mimikatz" %}
```
12/04/2024 02:51:34 PM
LogName=Security
EventCode=4688
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=138960
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
	New Process ID:		0x1764
	New Process Name:	C:\Users\Administrator\Downloads\mimikatz.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0x14c8
	Creator Process Name:	C:\Windows\System32\cmd.exe
	Process Command Line:	mimikatz.exe  "lsadump::lsa /inject" exit
```
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://ipurple.team/2024/07/15/sharphound-detection/](https://ipurple.team/2024/07/15/sharphound-detection/)
2. [https://community.splunk.com/t5/Splunk-Search/How-to-ignore-case-sensitive-input-in-lookup-files/td-p/296763](https://community.splunk.com/t5/Splunk-Search/How-to-ignore-case-sensitive-input-in-lookup-files/td-p/296763)
3. [https://docs.splunk.com/Documentation/LookupEditor/4.0.4/User/CreateLookup](https://docs.splunk.com/Documentation/LookupEditor/4.0.4/User/CreateLookup)
