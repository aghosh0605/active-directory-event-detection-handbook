# A Kerberos service ticket was requested

### Event Description

* **Event ID 4769**: This event is logged whenever a Kerberos service ticket (TGS ticket) is requested by an account. It provides details such as the requesting account, the service principal name (SPN), and the ticket encryption type. Monitoring this event is crucial for detecting abnormal service ticket requests, which may indicate lateral movement or attempts to exploit Kerberos (e.g., Pass-the-Ticket or Kerberoasting attacks).

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

1. **Simulating Normal Kerberos Service Ticket Requests**:
   * Log in to a domain-joined machine.
   * Access a network resource, such as a shared folder or a web application, that requires authentication using Kerberos.
   * Check **Event Viewer** > **Windows Logs** > **Security** for **Event ID 4769**.
2. **Simulating Abnormal Ticket Requests**:
   *   Use a penetration testing tool or script to simulate abnormal ticket requests. For example, use the `GetUserSPNs` script in PowerShell for Kerberoasting:

       ```powershell
       GetUserSPNs -Domain "example.com" -Username "username" -Password "password"
       ```
   * Verify that **Event ID 4769** is logged for each ticket request and includes the SPNs requested.
3. **Manual Testing**:
   *   Use the `klist` command to purge tickets and initiate a new service ticket request:

       ```powershell
       klist purge
       ```
   * Access a Kerberos-authenticated service and confirm that the event is logged.

***

### Event Viewer Logs

_Attach the exported event logs for Event ID 4769 here._

***

### Splunk Queries

> _(Placeholder for Splunk queries; add your custom detection logic here for monitoring Kerberos service ticket requests.)_

***

### Splunk Logs

_Attach relevant Splunk log outputs here to demonstrate detected ticket requests._

***

### Splunk Alert

> _(Describe the alerting logic, thresholds, and any automated response actions.)_

***

### Sigma Rules

> _(Provide the Sigma rule content or details on how to translate this use case into a Sigma rule.)_

***

This documentation ensures comprehensive coverage for detecting and analyzing Kerberos service ticket requests logged by Event ID 4769. Let me know if additional scenarios or refinements are needed!
