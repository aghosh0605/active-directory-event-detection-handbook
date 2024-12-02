# Registry Value Modified

### Event Description

* **Event ID 4657**: This event is logged when a registry key or value is modified. It includes details such as the user or process responsible for the change, the registry key or value affected, and the type of modification. Monitoring this event is crucial for detecting unauthorized registry changes that may indicate malware activity or policy violations.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Simulate a Registry Modification:**

* Open **Registry Editor** (`regedit`).
* Navigate any audited registry key.
* Modify or delete a value under the key.
* Check **Event Viewer** > **Windows Logs** > **Security** for **Event ID 4657**.
{% endtab %}

{% tab title="CMD" %}
#### **Registry Value Types**

| Type                | Description                      | CMD Syntax         | PowerShell Syntax        |
| ------------------- | -------------------------------- | ------------------ | ------------------------ |
| **REG\_SZ**         | String                           | `/t REG_SZ`        | `-Value "string"`        |
| **REG\_DWORD**      | 32-bit unsigned integer          | `/t REG_DWORD`     | `-Value 1`               |
| **REG\_QWORD**      | 64-bit unsigned integer          | `/t REG_QWORD`     | `-Value 1`               |
| **REG\_MULTI\_SZ**  | Multi-line text                  | `/t REG_MULTI_SZ`  | `-Value "Line1","Line2"` |
| **REG\_EXPAND\_SZ** | Expandable string with variables | `/t REG_EXPAND_SZ` | `-Value "C:\%Path%"`     |

Add a registry value. Add `/f`: Force overwrite without confirmation to edit any value.

<pre class="language-batch"><code class="lang-batch"><strong>reg add HKLM\Software\TestKey /v TestValue /t REG_SZ /d "TestData"
</strong></code></pre>

Delete a registry value and key

```batch
:: Remove the value only
reg delete HKLM\Software\TestKey /v TestValue /f
:: Delete the whole key
reg delete HKLM\Software\TestKey /f
```
{% endtab %}

{% tab title="Powershell" %}
Create and Modify a Registry Value (PowerShell)

```powershell
New-Item -Path HKLM:\Software\TestKey
Set-ItemProperty -Path HKLM:\Software\TestKey -Name TestValue -Value "InitialData"
```

Get Registry Value

```powershell
Get-ItemProperty -Path HKLM:\Software\TestKey -Name TestValue
```

Remove a Registry Value

```powershell
Remove-ItemProperty -Path HKLM:\Software\TestKey -Name TestValue
```

Remove a Registry Key

```powershell
Remove-Item -Path HKLM:\Software\TestKey -Recurse
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
Turn on Advanced Audit Logging to get the logs for registry changes. Follow the steps [here](./).\
Now, changing system registry for testing is risky. So, follow the steps [here](./) to create a test registry and set registry key permissions for auditing.
{% endhint %}

### Event Viewer Logs

> Audit Success 02-12-2024 17:14:26 Microsoft Windows security auditing. 4657 Registry

***

### Splunk Queries

```splunk-spl
index=ad-test EventCode IN (4657) 
| stats count by index sourcetype host Subject_Account_Name dvc EventCode signature
```

***

### Splunk Logs

```
12/02/2024 05:14:26 PM
LogName=Security
EventCode=4657
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=119540
Keywords=Audit Success
TaskCategory=Registry
OpCode=Info
Message=A registry value was modified.

Subject:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-500
	Account Name:		administrator
	Account Domain:		TEST
	Logon ID:		0x3CFF4

Object:
	Object Name:		\REGISTRY\MACHINE\SOFTWARE\TestKey
	Object Value Name:	ad
	Handle ID:		0x35c
	Operation Type:		Existing registry value modified

Process Information:
	Process ID:		0x10ec
	Process Name:		C:\Windows\regedit.exe

Change Information:
	Old Value Type:		REG_SZ
	Old Value:		test2
	New Value Type:		REG_SZ
	New Value:		test
```

***

### Splunk Alerts

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
2. [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
3. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.4)
4. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty?view=powershell-7.4)
5. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-itemproperty?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-itemproperty?view=powershell-7.4)
6. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-itemproperty?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-itemproperty?view=powershell-7.4)
