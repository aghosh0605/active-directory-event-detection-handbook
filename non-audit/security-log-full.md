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
2. **Generate a High Volume of Security Events:**
   *   Use audit policies or scripts to create many security events.\
       Example PowerShell command:

       ```powershell
       for ($i = 0; $i -lt 10000; $i++) { Write-EventLog -LogName Security -Source Microsoft-Windows-Security-Auditing -EventId 4624 }
       ```
3. **Observe Event Log Full Condition:**
   * Monitor the **Event Viewer** for **Event ID 1104** indicating that the security log is full.
   * Capture the event details for further analysis.

***

### Event Viewer Logs



***

### Splunk Queries



***

### Splunk Logs



### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104)

***
