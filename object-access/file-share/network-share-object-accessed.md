# Network Share Object Accessed

### Event Description

* **Event ID 5140**: This event is logged when a network share object is accessed. It provides details about the share name, the account that accessed it, the accessed resource, and the type of access performed. Monitoring this event helps track unauthorized or unusual activity on shared resources.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
* **Enable File Sharing:**
  * Right-click on a folder (e.g., `C:\SharedFolder`) > **Properties**.
  * Go to the **Sharing** tab > Click **Advanced Sharing** > Check **Share this folder**.
  * Optionally, set permissions by clicking **Permissions** and assigning read/write access.
* **Access the Shared Folder**:
  *   On another machine or the same machine, press `Win + R`, type:

      ```batch
      \\<hostname>\SharedFolder
      ```

      Replace `<hostname>` with the machine’s name or IP address and `SharedFolder` with the shared folder's name.
{% endtab %}

{% tab title="CMD" %}
* Log in to a Windows system with access to shared resources.
* Access a shared folder or file using the UNC path (e.g., `\\<server_name>\<share_name>`).
*   Alternatively, map the shared drive using the following command in Command Prompt:

    ```batch
    net use Z: \\<server_name>\<share_name>
    ```
* Replace `<server_name>` with the hostname or IP of the file server and `<share_name>` with the name of the shared folder.
* Interact with the files within the share (e.g., open, copy, or edit).
*   Disconnect the mapped drive with:

    ```batch
    net use Z: /delete
    ```
{% endtab %}

{% tab title="Powershell" %}
When the shared folder is ready we can access it like below:

```batch
copy \\servername\sharefolder\somefile .
```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 05-12-2024 14:51:11 Microsoft Windows security auditing. 5140 File Share

***

### Splunk Queries

```splunk-spl
```

***

### Splunk Logs

_Attach relevant Splunk log outputs here to show detections of network share accesses._

***
