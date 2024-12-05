# Security Log Full

### Event Description

* **Event ID 1104**: This event is logged when the Windows Security Event Log is full, and the configured action for such an event is triggered (e.g., overwrite events, clear logs, or stop logging). Monitoring this event is crucial as a full security log may indicate a deliberate attempt to overwrite or suppress important audit information.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

1. **Set the Security Log to a Fixed Size:**
   * Open the **Event Viewer** (`eventvwr.msc`).
   * Navigate to **Windows Logs** > **Security**.
   * Right-click **Security** and select **Properties**.
   * Set the **Maximum log size** to a small value (e.g., 1 MB) to easily trigger the log full condition.
   * Configure the action to **Do not overwrite events** or **Overwrite events as needed** for testing purposes.
2. **Observe Event Log Full Condition:**
   * Monitor the **Event Viewer** for **Event ID 1104** indicating that the security log is full.
   * Capture the event details for further analysis.

***

### Event Viewer Logs

> Audit Success 04-12-2024 13:31:19 Eventlog 1104 Event processing

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode=1100
|stats values(Message) as message values(signature) as signature  values(host) as host values(ComputerName) as ComputerName count by index sourcetype EventCode dest
```
{% endcode %}

***

### Splunk Logs

```
12/04/2024 05:34:50 PM
LogName=Security
EventCode=1100
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft-Windows-Eventlog
Type=Information
RecordNumber=142849
Keywords=Audit Success
TaskCategory=Service shutdown
OpCode=Info
Message=The event logging service has shut down.
```

### Splunk Alert

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104)

***
