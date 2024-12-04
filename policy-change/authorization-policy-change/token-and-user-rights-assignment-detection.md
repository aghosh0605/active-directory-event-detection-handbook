# Token and User Rights Assignment Detection

### Event Description

* **Event ID 4703**: This event is logged when a token right is adjusted. It provides details about the token right that was modified and the account that made the adjustment. Token rights define specific privileges assigned to a user or process token.
* **Event ID 4704**: This event is generated when a user right is assigned. It captures information about the right assigned, the target user or group, and the account responsible for the assignment. Monitoring this event helps track privilege assignments that could impact system security.
* **Event ID 4705**: This event is logged when a user right is removed. It includes details about the revoked right, the user or group affected, and the account performing the removal. Monitoring this event is critical to ensure essential privileges are not revoked unintentionally or maliciously.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

1. **Simulating Token Right Adjustment (Event ID 4703):**
   * Log in with administrative privileges.
   *   Use the following command in PowerShell to adjust a token right:

       ```powershell
       ntrights +r SeShutdownPrivilege -u <username>
       ```
   * Replace `<username>` with the target user or group.
   * Check **Event Viewer** under **Windows Logs** > **Security** for **Event ID 4703**.
2. **Assigning a User Right (Event ID 4704):**
   * Open **Local Security Policy** (`secpol.msc`) or use a Group Policy to assign a user right:
     * Navigate to **Security Settings** > **Local Policies** > **User Rights Assignment**.
     * Assign a specific user right (e.g., "Log on as a service") to a user or group.
   * Confirm **Event ID 4704** appears in the **Security** logs.
3. **Removing a User Right (Event ID 4705):**
   * Use **Local Security Policy** or Group Policy to remove a user right:
     * Navigate to **User Rights Assignment** and remove a privilege from a user or group.
   * Check **Event Viewer** for **Event ID 4705** to ensure the change was logged.

***

### Event Viewer Logs

_Attach the exported event logs for Event IDs 4703, 4704, and 4705 demonstrating token right adjustments, and user rights assignments or removals._

***

### Splunk Queries

> _(Placeholder for Splunk queries; insert your custom detection logic here for monitoring token and user rights changes.)_

***

### Splunk Logs

_Attach relevant Splunk log outputs here, showing detection of token and user rights changes._

***
