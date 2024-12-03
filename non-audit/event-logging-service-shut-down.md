# Event Logging Service Shut Down

### Event Description

* **Event ID 1100**: This event is logged when the Windows Event Log service is stopped. Monitoring this event is crucial as it can indicate potential tampering or disruption of logging, which attackers may perform to cover their tracks.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

1. **Simulate Stopping the Event Logging Service:**
   * Log in with administrative privileges on a Windows machine.
   * Open the **Services** console (`services.msc`).
   * Locate the **Windows Event Log** service and attempt to stop it.
   *   Alternatively, use the following command in an elevated PowerShell session to stop the service:

       ```powershell
       Stop-Service -Name "EventLog"
       ```
2. **Verify Event Logs:**
   * Open **Event Viewer** (`eventvwr.msc`).
   * Navigate to **Windows Logs** > **System**.
   * Look for **Event ID 1100**, which confirms the shutdown of the Windows Event Log service.
3. **Enable Auditing for Service Changes (if not already enabled):**
   * Open the **Group Policy Management Editor**.
   * Navigate to **Computer Configuration** > **Windows Settings** > **Security Settings** > **Advanced Audit Policy Configuration** > **System** > **Audit Other System Events**.
   * Enable auditing for both success and failure.

***

### Event Viewer Logs

_Attach the exported event logs for Event ID 1100 demonstrating the shutdown of the Event Logging service._

***

### Splunk Queries

> _(Placeholder for Splunk queries; insert your custom detection logic here for monitoring Event Logging service shutdowns.)_

***

### Splunk Logs

_Attach relevant Splunk log outputs here, showing detection of Event Logging service shutdowns._

***
