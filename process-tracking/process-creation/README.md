# Process Creation

## Command line process auditing <a href="#command-line-process-auditing" id="command-line-process-auditing"></a>

### Turn on&#x20;

The pre-existing process creation audit event ID 4688 will now include audit information for command line processes. It will also log the SHA1/2 hash of the executable in the Applocker event log (Application and Services Logs\Microsoft\Windows\AppLocker)\
\
You must have Audit Process Creation auditing enabled to see event ID 4688.

<details>

<summary>Turn on Audit Process Creation</summary>

**Policy location:** Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking

**Policy Name:** Audit Process Creation

**Supported on:** Windows 7 and above

**Description/Help:**

This security policy setting determines whether the operating system generates audit events when a process is created (starts) and the name of the program or user that created it.

These audit events can help you understand how a computer is being used and to track user activity.

Event volume: Low to medium, depending on system usage

**Default:** Not configured

</details>

To see the additions to event ID 4688, you must enable the new policy setting: Include command line in process creation events

<details>

<summary>Include command line in process creation events</summary>

**Path**:  Administrative Templates\System\Audit Process Creation \
**Setting**: Include the command line in process creation events. \
**Default setting**: Not Configured (not enabled) \
**Description**: This policy setting determines what information is logged in security audit events when a new process has been created. This setting only applies when the Audit Process Creation policy is enabled. If you enable this policy setting the command line information for every process will be logged in plain text in the security event log as part of the Audit Process Creation event 4688, "a new process has been created," on the workstations and servers on which this policy setting is applied.

If you disable or don't configure this policy setting, the process's command line information won't be included in Audit Process Creation events.

**Default**: Not configured

</details>

{% hint style="info" %}
**Note**: When this policy setting is enabled, any user with access to read the security events will be able to read the command line arguments for any successfully created process. Command line arguments can contain sensitive or private information such as passwords or user data.
{% endhint %}

When you use Advanced Audit Policy Configuration settings, you need to confirm that these settings aren't overwritten by basic audit policy settings. Event 4719 is logged when the settings are overwritten.&#x20;

<details>

<summary>Prevent overwritting by basic audit policy settings</summary>

1. Open the Group Policy Management console
2. Right-click Default Domain Policy, and then select Edit.
3. Double-click Computer Configuration, double-click Policies, and then double-click Windows Settings.
4. Double-click Security Settings, double-click Local Policies, and then select Security Options.
5. Double-click Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings, and then select Define this policy setting.
6. Select Enabled, and then select OK.

</details>

{% hint style="danger" %}
This change indeed causes Windows to rely exclusively on the subcategory-based advanced audit policies, which can make some event categories disappear if their specific subcategories aren’t configured.
{% endhint %}

### Verify Advanced Audit Policies

Follow the below process to ensure that the relevant subcategories are explicitly enabled since Windows will ignore the broader categories once the above setting is applied.

Use this command to view all subcategories and verify that they are set as needed:

```batch
auditpol /get /category:*
```

If any subcategory is set to "**No Auditing**", please verify if it needs to be enabled to get some specific logs. Enable them with the below procedure.

<details>

<summary>Enable Advanced Audit Policies</summary>

1. Go to **`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`**
2. Enable the necessary policies.
3. Run **`gpupdate /force`** in the Command Prompt to ensure the policy settings are updated.
4. Run the previously mentioned **auditpol** command again to verify the policies are properly enabled.

</details>

### References

1. [https://lantern.splunk.com/Security/Product\_Tips/Enterprise\_Security/Enabling\_Windows\_event\_log\_process\_command\_line\_logging\_via\_group\_policy\_object](https://lantern.splunk.com/Security/Product\_Tips/Enterprise\_Security/Enabling\_Windows\_event\_log\_process\_command\_line\_logging\_via\_group\_policy\_object)
2. [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
3. [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)
