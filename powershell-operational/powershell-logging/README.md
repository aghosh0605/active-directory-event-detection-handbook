# Powershell Logging

### Description

By logging PowerShell activity and analyzing the commands with Splunk UBA, you can identify indicators of compromise corresponding to malicious activity by a user or malware. PowerShell provides access to Windows API calls that attackers can exploit to gain elevated access to the system, avoiding antivirus and other security controls in the process. PowerShell is also internally utilized by popular hacking tools.

{% hint style="info" %}
The PowerShell model works best with PowerShell 5.0 or the latest version of PowerShell 4.0.
{% endhint %}

* PowerShell supports the following types of logging:
  * module logging
  * script block logging
  * transcription
* PowerShell events are written to the PowerShell operational log `Microsoft-Windows-PowerShell%4Operational.evtx`.

***

### Configuration

<details>

<summary>Configure module logging for PowerShell</summary>

1. In the Group Policy Management Editor, select `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`, and set **Turn on Module Logging** to enabled.
2. In the **Options** pane, select the button to show the Module Name.
3.  In the **Module Names** window, enter **\*** to record all modules.\


    <figure><img src="../../.gitbook/assets/Screenshot 2024-11-18 151907.png" alt=""><figcaption></figcaption></figure>
4. Select **OK** in the Module Names window.
5. Select **OK** in the Module Logging window.

</details>

<details>

<summary>Configure script block logging for PowerShell</summary>

To enable script block logging, go to the Windows PowerShell GPO settings and set **Turn on PowerShell Script Block Logging** to enabled.

The steps are already written above. In the same folder just enable **Turn on PowerShell Script Block Logging.**

</details>

In addition, turn on command line process auditing. You can find instructions [here](../../process-tracking/process-creation/).

<details>

<summary>Configure transcription logging</summary>

1. In Group Policy Management Editor through `Windows Components > Administrative Templates > Windows PowerShell`
2. Enable the **Turn on PowerShell Transcription** feature.

</details>

{% hint style="warning" %}
Splunk Enterprise does not support protected event logging. If your events are encrypted, decrypt them before ingesting to UBA. For details, see [here](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2#enabling-script-block-logging).
{% endhint %}

***

### Verification

To verify that PowerShell logging is properly configured, look for the following PowerShell activity events in Splunk UBA:

* EventCode = 4103
* EventCode = 4104
* EventCode = 4688 and Process\_Name contains PowerShell
* EventCode = 7045 and Process\_Name contains PowerShell

### Event Description

* **Event ID 4103**: **Module logging** - This event is logged when a PowerShell script executes, providing a detailed script block logging trail. It captures executed commands or scripts, aiding in identifying potentially malicious or unauthorized PowerShell activity.
* **Event ID 4104**: **Powershell Script Block Logging** - This event logs the contents of a PowerShell script block, including all commands and parameters passed during execution. It is invaluable for detecting and analyzing suspicious PowerShell usage.

### References

1. [https://docs.splunk.com/Documentation/UBA/5.4.1/GetDataIn/AddPowerShell](https://docs.splunk.com/Documentation/UBA/5.4.1/GetDataIn/AddPowerShell)
2. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about\_logging\_windows?view=powershell-7.4\&viewFallbackFrom=powershell-7.2](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.4\&viewFallbackFrom=powershell-7.2)
3. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about\_eventlogs?view=powershell-5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
