# 4688

### Event Description

*   **Event ID 4688**: This event is logged whenever a new process is created. It includes details like the process ID, process name, command line arguments, and the user or service that initiated the process.

    Monitoring Event ID 4688 is essential for tracking potential malicious activities, such as unauthorized PowerShell commands or suspicious downloads, which may indicate a security breach.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="CMD" %}
```bash
# Download with curl.exe and use -o to save the file in path
curl https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE -o LICENSE
```
{% endtab %}

{% tab title="Powershell" %}
**Simulating Process Creation with PowerShell**:

*   Run the following command to use PowerShell's `Invoke-WebRequest` cmdlet to download a file from the internet:

    ```powershell
    Invoke-WebRequest -Uri "http://example.com/file.txt" -OutFile "C:\Users\Public\Downloads\file.txt"
    # wget is another option
    wget https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE -outFile LICENSE
    ```
* This command initiates a process that downloads a file from the specified URL and saves it to the designated directory.
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 13-11-2024 10:22:34 Microsoft Windows security auditing. 4688 Process Creation\
> Information 14-11-2024 11:44:36 PowerShell (PowerShell) 800 Pipeline Execution Details

***

### Splunk Queries

> _(Placeholder for Splunk queries; add your custom Splunk detection logic here to monitor for suspicious PowerShell command executions.)_

***

### Splunk Logs

{% tabs %}
{% tab title="curl" %}
```
11/14/2024 11:41:44 AM
LogName=Security
EventCode=4688
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=37467
Keywords=Audit Success
TaskCategory=Process Creation
OpCode=Info
Message=A new process has been created.

Creator Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x2EA05B

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x1200
	New Process Name:	C:\Windows\System32\curl.exe
	Token Elevation Type:	TokenElevationTypeDefault (1)
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0x1470
	Creator Process Name:	C:\Windows\System32\cmd.exe
	Process Command Line:	curl  https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE -o LICENSE
```

Here **Process Command Line** is important as it contains the raw command used to download the file.
{% endtab %}

{% tab title="Invoke-webrequest" %}
```
11/14/2024 11:44:36 AM
LogName=Windows PowerShell
EventCode=800
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=PowerShell
Type=Information
RecordNumber=7948
Keywords=Classic
TaskCategory=Pipeline Execution Details
OpCode=Info
Message=Pipeline execution details for command line: wget https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE  -outFile LICENSE. 

Context Information: 
	DetailSequence=1
	DetailTotal=1

	SequenceNumber=63

	UserId=TEST\administrator
	HostName=ConsoleHost
	HostVersion=5.1.20348.558
	HostId=2afe4743-0cba-4277-b959-fd6993693741
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	EngineVersion=5.1.20348.558
	RunspaceId=dae2ee39-29d2-4011-9f52-238607ed273e
	PipelineId=28
	ScriptName=
	CommandLine=wget https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE  -outFile LICENSE 

Details: 
CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"
ParameterBinding(Invoke-WebRequest): name="OutFile"; value="LICENSE"
ParameterBinding(Invoke-WebRequest): name="Uri"; value="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/LICENSE"
```

Here **CommandLine** is important as it contains the raw command used to download the file.&#x20;
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
Scripts executed in PowerShell do not generate Event ID **4688** (Process Creation) in the Security log because PowerShell commands are interpreted scripts, not standalone executable files like `.exe` or `.msi` files. Instead, PowerShell script activities are logged under **Applications and Services Logs > Windows PowerShell > Operational** in Event Viewer. The event IDs for PowerShell script executions in this log are specific to PowerShell and do not align with **4688**, which is only triggered for direct process creations.
{% endhint %}

To get raw commands for **Powershell**, follow the guide [here](broken-reference).

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
2. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.4)

***

This format covers all necessary components, with the Event Viewer logs section where you can attach the specific logs for reference. Let me know if there’s anything more you’d like to add!
