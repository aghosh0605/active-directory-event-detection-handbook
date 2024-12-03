# Security Log Clear

### Event Description

* **Event ID 1102**: This event is logged when the security log is cleared on a Windows system. It is critical to monitor this event, as clearing the security logs may indicate an attempt to cover malicious activities. The event includes details about the account responsible for clearing the logs.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Simulating Security Log Clearing:**

* Log in to the system with administrative privileges.
* Open **Event Viewer**.
* Navigate to **Windows Logs** > **Security**.
* Right-click on **Security** and select **Clear Log**.
* Save the logs if prompted.
* Check **Event Viewer** for **Event ID 1102** under **Windows Logs** > **Security** to verify that the action was logged.
{% endtab %}

{% tab title="CMD" %}
* **Open CMD with Administrative Privileges**.
*   Clear the security log using the `wevtutil` command:

    ```batch
    wevtutil cl Security
    ```
{% endtab %}

{% tab title="Powershell" %}
* **Open PowerShell with Administrative Privileges**.
*   Clear the security log using the following cmdlet:

    ```powershell
    Clear-EventLog -LogName Security
    ```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 02-12-2024 12:24:26 Eventlog 1102 Log clear

{% hint style="info" %}
Event ID 104 will be created in System Logs if the system log is cleared. Tracking whether system logs are cleared or not is necessary as the [Unexpected WMI Shutdown](../system/other-system-events/unexpected-wmi-shutdown.md) use case depends on System Logs.
{% endhint %}

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(1102) |fillnull value=unknown EventCode dest
|stats values(Message) as message values(signature) as signature values(User) as user values(host) as host values(ComputerName) as ComputerName count by index sourcetype EventCode dest
```
{% endcode %}

***

### Splunk Logs

```
12/02/2024 12:24:26 PM
LogName=Security
EventCode=1102
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft-Windows-Eventlog
Type=Information
RecordNumber=112768
Keywords=Audit Success
TaskCategory=Log clear
OpCode=Info
Message=The audit log was cleared.
Subject:
	Security ID:	S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:	administrator
	Domain Name:	TEST
	Logon ID:	0x3CFF4
```

***

### Splunk Alert

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

***

### Sigma Rules

<details>

<summary>Event log cleared (native)</summary>

```yaml
title: Event log cleared (native)
description: Detects scenarios where an attacker cleared the event logs.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0005-Defense%20Evasion/T1070.001-Clear%20Windows%20event%20logs
tags:
- attack.defense_evasion
- attack.t1070.001 # Indicator Removal: Clear Windows Event Logs 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security, system
detection:
  selection:
    EventID:
      - 1102 # Security event log cleared (reported in Security channel). Attention, this Event ID is also produced by ADFS in the same Channel
      - 104  # Other event log cleared (reported in System channel).
  condition: selection
falsepositives:
- Exchange Servers
level: high
```

```splunk-spl
source=WinEventLog:* AND (EventID="1102" OR EventID="104")
```

</details>

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
2. [Windows event log cleared](https://lantern.splunk.com/Security/UCE/Guided_Insights/Threat_hunting/Detecting_a_ransomware_attack/Windows_event_log_cleared)
