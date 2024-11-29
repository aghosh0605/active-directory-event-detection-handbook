# Other Object Access Events

### Enable Auditing in Advanced Audit Policy

1. Open **Group Policy Editor**:
   * Press `Win + R`, type `gpedit.msc`, and press **Enter**.
   *   Navigate to:

       {% code overflow="wrap" %}
       ```
       Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access
       ```
       {% endcode %}
2. Enable **Audit Other Object Access Events**:
   * Double-click **Audit Other Object Access Events**.
   * Check both **Success** and **Failure** according to the need.
   * Click **Apply**, then **OK**.
3.  Apply the policy: Run the following command to apply the settings:

    ```cmd
    gpupdate /force
    ```
