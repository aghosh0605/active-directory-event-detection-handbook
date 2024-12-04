# Unexpected WMI Shutdown

### Event Description

* **Event ID 1074**: This event is logged when a system shutdown or restart is initiated. It captures details such as:
  * The reason for the shutdown or restart.
  * The process or user is responsible for initiating it.
  * Additional comments (if provided). Monitoring this event is crucial for detecting unauthorized or unexpected shutdowns, which could impact system availability and security.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Initiate a Restart or Shutdown**:

* Press `Ctrl + Alt + Del`, then click the **Power** button in the bottom-right corner.
* Select **Restart** or **Shutdown**.
{% endtab %}

{% tab title="CMD" %}
* **Simulating System Shutdown:**
  * Open **Command Prompt** with administrative privileges.
  *   Execute the following command to shut down:

      ```batch
      shutdown /s /t 0
      ```
  * After the system shuts down, check **Event Viewer** > **Windows Logs** > **System** for **Event ID 1074**.
* **Simulating System Restart:**
  *   In **Command Prompt**, execute the command below to restart the system:

      ```batch
      shutdown /r /t 0
      ```
  * Verify that **Event ID 1074** is logged in **Event Viewer** with the appropriate details.
* **Abort a Scheduled Shutdown or Restart (Optional):**
  *   To cancel a pending shutdown or restart, run:

      ```batch
      shutdown /a
      ```
  * Ensure that **Event Viewer** does not log a shutdown/restart in this case.
{% endtab %}

{% tab title="Powershell" %}
* Open PowerShell with administrative privileges.
*   Run the following command to restart the system:

    ```powershell
    Restart-Computer -Force
    ```

    Or, shut down the system:

    ```powershell
    Stop-Computer -Force
    ```
* After the system restarts, check **Event Viewer** for Event ID 1074.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
The logs can be found at the location below.\
**Event Viewer > Windows Logs > System > User Filter for 1074**
{% endhint %}

***

### Event Viewer Logs

> Information 02-12-2024 11:35:15 User32 1074 None

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(1074) |eval user=lower(user) |fillnull value=unknown dest 
|stats values(Reason_Code) as reason_Code values(LogName) as log_name values(Message) as message values(Shutdwon_Type) as shutdown_type values(seeverity) as severity values(user) as user count by index sourcetype host dest EventCode
```
{% endcode %}

***

### Splunk Logs

```
11/29/2024 05:12:36 PM
LogName=System
EventCode=1074
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=User32
Type=Information
RecordNumber=10271
Keywords=Classic
TaskCategory=None
OpCode=None
Message=The process C:\Windows\System32\RuntimeBroker.exe (WIN-3BK7E06Q35B) has initiated the power off of computer WIN-3BK7E06Q35B on behalf of user TEST\Administrator for the following reason: Other (Unplanned)
 Reason Code: 0x5000000
 Shutdown Type: power off
 Comment:
```

***

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-computer?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-computer?view=powershell-7.4)
2. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restart-computer?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restart-computer?view=powershell-7.4)
3. [https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/identify-cause-of-wmi-shutdown](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/identify-cause-of-wmi-shutdown)
