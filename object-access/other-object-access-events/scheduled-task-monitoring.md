# Scheduled Task Monitoring

### Event Description

* **Event ID 4698**: Logged when a new scheduled task is created. It includes details such as the task name, creator, and task actions.
* **Event ID 4699**: Logged when a scheduled task is deleted. It helps track the removal of automated tasks.
* **Event ID 4700**: Logged when a scheduled task is enabled. Monitoring this event ensures detection of unauthorized re-enabling of tasks.
* **Event ID 4701**: Logged when a scheduled task is disabled. It captures actions where tasks are intentionally or unintentionally stopped.
* **Event ID 4702**: Logged when the properties of a scheduled task are updated. It records changes that may alter task behavior.

Monitoring these events collectively is critical to detect unauthorized task creation, modification, or deletion, which can be indicative of persistence mechanisms in attacks.

{% hint style="warning" %}
Kindly enable the respective audit policy to get the logs. Follow the steps mentioned [here](./).
{% endhint %}

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Simulating Scheduled Task Events via GUI**:

* Open **Task Scheduler** on a Windows system.
* Perform the following actions one by one:
  * Create a new task (Event ID 4698).
  * Delete an existing task (Event ID 4699).
  * Enable a disabled task (Event ID 4700).
  * Disable an enabled task (Event ID 4701).
  * Modify properties of an existing task (Event ID 4702).
* Check **Event Viewer** > **Windows Logs** > **Security** for the corresponding events.&#x20;
{% endtab %}

{% tab title="CMD" %}
*   **Create a Task (Event ID 4698):**\
    This event is logged when a new scheduled task is created. It includes details such as the task name, creator, and actions.\
    Command to create a new scheduled task:

    ```batch
    schtasks /create /tn "TestTask" /tr "notepad.exe" /sc once /st 12:00
    ```
*   **Delete a Task (Event ID 4699):**\
    This event is logged when a scheduled task is deleted, helping to track the removal of automated tasks.\
    Command to delete an existing scheduled task:

    ```batch
    schtasks /delete /tn "TestTask" /f
    ```
*   **Enable a Task (Event ID 4700):**\
    This event is logged when a scheduled task is enabled. Monitoring this event ensures detection of unauthorized re-enabling of tasks.\
    Command to enable an existing scheduled task:

    ```batch
    schtasks /change /tn "TestTask" /enable
    ```
*   **Disable a Task (Event ID 4701):**\
    This event is logged when a scheduled task is disabled. It captures actions where tasks are intentionally or unintentionally stopped.\
    Command to disable an existing scheduled task:

    ```batch
    schtasks /change /tn "TestTask" /disable
    ```
*   **Modify Task Properties (Event ID 4702):**\
    This event is logged when the properties of a scheduled task are updated. It records changes that may alter task behavior.\
    Command to update the properties of an existing task:

    ```batch
    schtasks /change /tn "TestTask" /st 14:00
    ```
*   **Get Task Properties:**\
    Get details about a scheduled tasks or verify a task.

    ```batch
    schtasks /query /tn "TestTask" /fo LIST /v
    ```
{% endtab %}

{% tab title="Powershell" %}
**Using PowerShell for Task Operations**:

* Use the following commands to generate logs:
  *   **Create a Task**:

      ```powershell
      $action = New-ScheduledTaskAction -Execute 'notepad.exe'
      $trigger = New-ScheduledTaskTrigger -AtLogOn -Once
      Register-ScheduledTask -TaskName "TestTask" -Action $action -Trigger $trigger
      ```
  *   **Delete a Task**:

      ```powershell
      Unregister-ScheduledTask -TaskName "TestTask" -Confirm:$false
      ```
  *   **Enable a Task**:

      ```powershell
      Enable-ScheduledTask -TaskName "TestTask"
      ```
  *   **Disable a Task**:

      ```powershell
      Disable-ScheduledTask -TaskName "TestTask"
      ```
  *   **Modify Task Properties**:

      ```powershell
      $Time = New-ScheduledTaskTrigger -At 12:00 -Once
      Set-ScheduledTask -TaskName "TestTask" -Trigger $Time
      ```
*   Confirm each action generates the corresponding event.\
    Find the scheduled task with

    ```powershell
    Get-ScheduledTask -TaskName "TestTask"
    ```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 29-11-2024 14:11:26 Microsoft Windows security auditing. 4698 Other Object Access Events&#x20;
>
> Audit Success 29-11-2024 14:06:44 Microsoft Windows security auditing. 4699 Other Object Access Events&#x20;
>
> Audit Success 29-11-2024 14:12:18 Microsoft Windows security auditing. 4700 Other Object Access Events&#x20;
>
> Audit Success 29-11-2024 14:11:57 Microsoft Windows security auditing. 4701 Other Object Access Events&#x20;
>
> Audit Success 29-11-2024 13:55:20 Microsoft Windows security auditing. 4702 Other Object Access Events

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(4698,4699,4700,4701,4702) (Task_Name!="*User_Feed_Synchronization*" AND Task_Name!="*Optimize Start Menu Cache Files*" AND Task_Name!="*GoogleUpdateTask*")
|fillnull value=unknown user |stats values(Task_Name) as task_name values(TaskCategory) as task_category values(object_category) as object_category values(dest) as dest values(action) as action values(status) as status values(signature) as signature by index sourcetype host EventCode user 
|rename user as Target_User,EventCode as event_code
```
{% endcode %}

***

### Splunk Logs

{% tabs %}
{% tab title="4698" %}
```
11/29/2024 02:11:26 PM
LogName=Security
EventCode=4698
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=103272
Keywords=Audit Success
TaskCategory=Other Object Access Events
OpCode=Info
Message=A scheduled task was created.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x7F621

Task Information:
	Task Name: 		\NoteTask
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\NoteTask</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-11-29T08:45:00Z</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>notepad.exe</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>TEST\administrator</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
</Task>

Other Information:
	ProcessCreationTime: 		8444249301321497
	ClientProcessId: 			240
	ParentProcessId: 			888
	FQDN: 		0
```
{% endtab %}

{% tab title="4699" %}
```
11/29/2024 02:06:44 PM
LogName=Security
EventCode=4699
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=103164
Keywords=Audit Success
TaskCategory=Other Object Access Events
OpCode=Info
Message=A scheduled task was deleted.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x7F621

Task Information:
	Task Name: 		\TestTask
	Task Content: 		

Other Information:
	ProcessCreationTime: 		8444249301321477
	ClientProcessId: 			3664
	ParentProcessId: 			5240
	FQDN: 		0
```
{% endtab %}

{% tab title="4700" %}
```
11/29/2024 02:12:18 PM
LogName=Security
EventCode=4700
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=103280
Keywords=Audit Success
TaskCategory=Other Object Access Events
OpCode=Info
Message=A scheduled task was enabled.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x7F621

Task Information:
	Task Name: 		\NoteTask
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\NoteTask</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-2889491314-2746541823-3071263440-500</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-11-29T14:15:00+05:30</StartBoundary>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>notepad.exe</Command>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		8444249301321497
	ClientProcessId: 			240
	ParentProcessId: 			888
	FQDN: 		0
```
{% endtab %}

{% tab title="4701" %}
```
11/29/2024 02:11:57 PM
LogName=Security
EventCode=4701
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=103279
Keywords=Audit Success
TaskCategory=Other Object Access Events
OpCode=Info
Message=A scheduled task was disabled.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x7F621

Task Information:
	Task Name: 		\NoteTask
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\NoteTask</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-2889491314-2746541823-3071263440-500</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <Enabled>false</Enabled>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-11-29T14:15:00+05:30</StartBoundary>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>notepad.exe</Command>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		8444249301321497
	ClientProcessId: 			240
	ParentProcessId: 			888
	FQDN: 		0
```
{% endtab %}

{% tab title="4702" %}
```
11/29/2024 01:55:20 PM
LogName=Security
EventCode=4702
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=102899
Keywords=Audit Success
TaskCategory=Other Object Access Events
OpCode=Info
Message=A scheduled task was updated.

Subject:
	Security ID:		S-1-5-18
	Account Name:		WIN-3BK7E06Q35B$
	Account Domain:		TEST
	Logon ID:		0x3E7

Task Information:
	Task Name: 		\Microsoft\Windows\WindowsUpdate\Scheduled Start
	Task New Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Source>Microsoft Corporation.</Source>
    <Author>Microsoft Corporation.</Author>
    <Description>This task is used to start the Windows Update service when needed to perform scheduled operations such as scans.</Description>
    <URI>\Microsoft\Windows\WindowsUpdate\Scheduled Start</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-11-29T11:25:01Z</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>PT1M</RandomDelay>
    </TimeTrigger>
    <SessionStateChangeTrigger>
      <Enabled>false</Enabled>
      <StateChange>ConsoleDisconnect</StateChange>
    </SessionStateChangeTrigger>
    <SessionStateChangeTrigger>
      <Enabled>false</Enabled>
      <StateChange>RemoteDisconnect</StateChange>
    </SessionStateChangeTrigger>
    <WnfStateChangeTrigger>
      <Enabled>false</Enabled>
      <StateName>7508BCA3380C960C</StateName>
      <Data>01</Data>
      <DataOffset>0</DataOffset>
    </WnfStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <RunLevel>LeastPrivilege</RunLevel>
      <UserId>NT AUTHORITY\SYSTEM</UserId>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>C:\Windows\system32\sc.exe</Command>
      <Arguments>start wuauserv</Arguments>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		8444249301319696
	ClientProcessId: 			372
	ParentProcessId: 			664
	FQDN: 		0
Collapse
```
{% endtab %}
{% endtabs %}

***

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

***

### Sigma Rules

<details>

<summary>Fortinet APT group abuse on Windows (task)</summary>

```yaml
title: Fortinet APT group abuse on Windows (task)
description: Detects scenarios where APT actors exploits Fortinet vulnerabilities to gain access into Windows infrastructure.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/EVTX_full_APT_attack_steps
- https://www.aha.org/system/files/media/file/2021/05/fbi-flash-tlp-white-apt-actors-exploiting-fortinet-vulnerabilities-to-gain-access-for-malicious-activity-5-27-21.pdf
- https://www.securityweek.com/fbi-shares-iocs-apt-attacks-exploiting-fortinet-vulnerabilities
tags:
- attack.execution
- attack.t1053.005
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    TaskName|endswith: '\SynchronizeTimeZone'
  condition: selection
falsepositives:
- None
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="4698" AND TaskName="*\\SynchronizeTimeZone")
```
{% endcode %}

</details>

<details>

<summary>Scheduled persistent task with SYSTEM privileges creation</summary>

```yaml
title: Scheduled persistent task with SYSTEM privileges creation
description: Detects scenarios where an attacker creates a privileged task to establish persistence.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0002-Execution/T1053.005-Scheduled%20Task
- https://www.ired.team/offensive-security/persistence/t1053-schtask
- https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/
- http://www.fuzzysecurity.com/tutorials/19.html
- https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce
- https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
- https://www.darkoperator.com/blog/2009/4/11/abusing-the-scheduler-with-meterpreter.html
- https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
- https://strontic.github.io/xcyclopedia/library/schtasks.exe-5BD86A7193D38880F339D4AFB1F9B63A.html
- https://redcanary.com/blog/microsoft-exchange-attacks/
- https://nasbench.medium.com/behind-the-detection-schtasks-eb67a33a8710
- https://www.linkedin.com/pulse/lolbin-attacks-scheduled-tasks-t1503005-how-detect-them-v%C3%B6gele
tags:
- attack.execution
- attack.t1053.005
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection: # Full command: "schtasks /create /sc minute /mo 1 /tn eviltask /tr C:\tools\shell.cmd /ru SYSTEM"
  selection:
    NewProcessName|endswith: \schtasks.exe
    CommandLine|contains|all:
      - create
      #- ru      # Run with privileges from user X
      #- SYSTEM  # Run with SYSTEM privileges
      - tr      # Program, path or command to run
      - sc      # Run task every X minutes
  condition: selection
falsepositives:
- Administrator
level: high

# Extract ID 4698
# <?xml version="1.0" encoding="UTF-16"?> <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"> <RegistrationInfo> <Date>2021-04-21T13:30:00</Date> <Author>demo\user1</Author> <URI>\eviltask</URI> </RegistrationInfo> <Triggers> <TimeTrigger> <Repetition> <Interval>PT1M</Interval> <StopAtDurationEnd>false</StopAtDurationEnd> </Repetition> <StartBoundary>2021-04-21T13:30:00</StartBoundary> <Enabled>true</Enabled> </TimeTrigger> </Triggers> <Settings> <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy> <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries> <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries> <AllowHardTerminate>true</AllowHardTerminate> <StartWhenAvailable>false</StartWhenAvailable> <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable> <IdleSettings> <Duration>PT10M</Duration> <WaitTimeout>PT1H</WaitTimeout> <StopOnIdleEnd>true</StopOnIdleEnd> <RestartOnIdle>false</RestartOnIdle> </IdleSettings> <AllowStartOnDemand>true</AllowStartOnDemand> <Enabled>true</Enabled> <Hidden>false</Hidden> <RunOnlyIfIdle>false</RunOnlyIfIdle> <WakeToRun>false</WakeToRun> <ExecutionTimeLimit>PT72H</ExecutionTimeLimit> <Priority>7</Priority> </Settings> <Actions Context="Author"> <Exec> <Command>C:\tools\shell.cmd</Command> </Exec> </Actions> <Principals> <Principal id="Author"> <UserId>S-1-5-18</UserId> <RunLevel>LeastPrivilege</RunLevel> </Principal> </Principals> </Task>
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (NewProcessName="*\\schtasks.exe" AND (CommandLine="*create*" AND CommandLine="*tr*" AND CommandLine="*sc*"))
```
{% endcode %}

</details>

<details>

<summary>Scheduled task created and deleted fastly (ATexec.py)</summary>

```yaml
title: Scheduled task created and deleted fastly (ATexec.py)
description: Detects scenarios where an attacker abuse task scheduler capacities to execute commands or elevate privileges.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0002-Execution/T1053.005-Scheduled%20Task
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py
- https://u0041.co/blog/post/1
- https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
tags:
- attack.execution
- attack.t1053.005 # Scheduled Task/Job: Scheduled Task 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_create:
    EventID: 4698
  selection_delete:
    EventID: 4699
  #filter:
  #  SubjectUserSid: 'S-1-5-18'
  condition: selection_create > selection_delete | group(Computer, TaskName)
  timeframe: 5m
falsepositives:
- Rare application activity
level: high
```

```
// Need to figure out!
```

</details>

<details>

<summary>Stickey key called CMD via command execution (hash detection)</summary>

```yaml
title: Stickey key called CMD via command execution (hash detection)
description: Detects scenarios where an attacker calls the stickey key and execute CMD.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0004-Privilege%20Escalation/T1546-Image%20File%20Execution%20Options%20Injection
- https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
- https://www.mandiant.com/resources/apt29-domain-frontin
- https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign-v1.pdf
requirements: have an up to date inventory for CMD hashes of your environment
tags:
- attack.privilege_escalation
- attack.t1546.008
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith: \winlogon.exe
    Hashes|contains: # SHA1 hash of CMD.exe
    - 99AE9C73E9BEE6F9C76D6F4093A9882DF06832CF # Windows 10 x64 v10.0.14393.0
    - 8C5437CD76A89EC983E3B364E219944DA3DAB464 # Windows 10 x64 v10.0.17763.0
    - 8DCA9749CD48D286950E7A9FA1088C937CBCCAD4 # Windows 10 x64 v10.0.18363.0
    - F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D # Windows 10 x64 v10.0.18363.0
  condition: selection
falsepositives:
- None
level: high
```

{% code overflow="wrap" %}
```splunk-spl
source=WinEventLog:Security AND (EventID="1" AND ParentImage="*\\winlogon.exe" AND (Hashes="*99AE9C73E9BEE6F9C76D6F4093A9882DF06832CF*" OR Hashes="*8C5437CD76A89EC983E3B364E219944DA3DAB464*" OR Hashes="*8DCA9749CD48D286950E7A9FA1088C937CBCCAD4*" OR Hashes="*F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D*"))
```
{% endcode %}

</details>

### References

1. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps)
2. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2025-ps)
3. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/unregister-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/unregister-scheduledtask?view=windowsserver2025-ps)
4. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps)
5. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps)
6. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2025-ps)
7. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps)

***
