# Registry

### **Enable Registry Auditing:**

* Open the **Group Policy Management Console (GPMC)**.
* Navigate to **Computer Configuration** > **Windows Settings** > **Security Settings** > **Advanced Audit Policy Configuration**.
* Expand **Object Access** and enable the **Audit Registry** policy for both Success and Failure events.
*   Apply the changes and update the group policy using the command:

    ```cmd
    gpupdate /force
    ```

### **Set Registry Key Permissions for Auditing:**

* Open **Registry Editor** (`regedit`).
* Navigate to the registry key you wish to monitor (e.g., `HKEY_LOCAL_MACHINE\SOFTWARE\TestKey`).
* Right-click the key, select **Permissions**, and click **Advanced**.
* In the **Auditing** tab, add an entry to audit changes made by specific users or groups.
