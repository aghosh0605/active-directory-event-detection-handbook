# Scheduled Task Monitoring

### Event Description

* **Event ID 4698**: Logged when a new scheduled task is created. It includes details such as the task name, creator, and task actions.
* **Event ID 4699**: Logged when a scheduled task is deleted. It helps track the removal of automated tasks.
* **Event ID 4700**: Logged when a scheduled task is enabled. Monitoring this event ensures detection of unauthorized re-enabling of tasks.
* **Event ID 4701**: Logged when a scheduled task is disabled. It captures actions where tasks are intentionally or unintentionally stopped.
* **Event ID 4702**: Logged when the properties of a scheduled task are updated. It records changes that may alter task behavior.

Monitoring these events collectively is critical to detect unauthorized task creation, modification, or deletion, which can be indicative of persistence mechanisms in attacks.

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

{% endtab %}

{% tab title="4699" %}

{% endtab %}

{% tab title="4700" %}

{% endtab %}

{% tab title="4701" %}

{% endtab %}

{% tab title="4702" %}

{% endtab %}
{% endtabs %}

***

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

***

### Sigma Rules



### References

1. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2025-ps)
2. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2025-ps)
3. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/unregister-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/unregister-scheduledtask?view=windowsserver2025-ps)
4. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps)
5. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps)
6. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2025-ps)
7. [https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps)

***
