# File Share

### Steps to Enable Object Access - File Share Auditing

1. Open **Group Policy Editor**:
   * Press `Win + R`, type `gpmc.msc`, and press Enter.
   * Right-click the GPO > Select **Edit**.
2.  Navigate to:

    ```
    Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access
    ```
3. Locate and double-click **Audit File Share**.
4. Enable the checkboxes for **Success** and/or **Failure** (depending on the logs you need).
5. Click **Apply** and **OK**.
6. Open Command Prompt as an administrator.
   *   Run:

       ```batch
       gpupdate /force
       ```
