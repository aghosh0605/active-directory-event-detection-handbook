# Domain Policy was changed

### Event Description

* **Event ID 4739**: This event is logged when a domain-wide security policy is modified. It provides details about the domain being affected, the specific policy changes, and the account responsible for initiating the change. Monitoring this event is critical to track changes in security posture and detect unauthorized modifications to domain-wide settings.

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}
**Simulating Domain Policy Change:**

* Log in to a **domain controller** with administrative privileges.
* Open **Group Policy Management**.
* Navigate to a domain-level Group Policy Object (GPO) such as **Default Domain Policy**.
* Modify any security setting, such as password policies or account lockout thresholds.
* Save the changes and apply the updated policy.
* Open **Event Viewer** > **Windows Logs** > **Security**, and locate **Event ID 4739** to verify the changes were logged.
{% endtab %}

{% tab title="CMD" %}
* **Open CMD with Administrative Privileges on a Domain Controller**.
*   Use the `net accounts` command to modify the domain password policy:

    <pre class="language-batch"><code class="lang-batch"><strong>net accounts /minpwlen:10
    </strong></code></pre>

    * This command sets the minimum password length for domain users to 10 characters.
{% endtab %}

{% tab title="Powershell" %}
* **Open PowerShell with Administrative Privileges on a Domain Controller**.
*   Modify a domain policy attribute, such as the **LockoutThreshold**:

    ```powershell
    Set-ADDefaultDomainPasswordPolicy -Identity "test.com" -LockoutThreshold 5
    ```

    Replace `test.com` with your actual domain name.
*   Check if the password policy is properly changed with::

    ```powershell
    Get-ADDefaultDomainPasswordPolicy
    ```
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 15-11-2024 12:18:02 Microsoft Windows security auditing. 4739 Authentication Policy Change

***

### Splunk Queries

{% code overflow="wrap" %}
```splunk-spl
index=ad-test EventCode IN(4739) |eval user=lower(user)|fillnull value=unknown action siganture user dest category
|stats values(Change_Type) as change_type count by index sourcetype host action EventCode signature user dest category
```
{% endcode %}

***

### Splunk Logs

```
10/25/2024 02:02:08 PM
LogName=Security
EventCode=4739
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=1988
Keywords=Audit Success
TaskCategory=Authentication Policy Change
OpCode=Info
Message=Domain Policy was changed.

Change Type:		Password Policy modified

Subject:
	Security ID:		S-1-5-18
	Account Name:		WIN-3BK7E06Q35B$
	Account Domain:		TEST
	Logon ID:		0x3E7

Domain:
	Domain Name:		TEST
	Domain ID:		S-1-5-21-2889491314-2746541823-3071263440

Changed Attributes:
	Min. Password Age:	\x01
	Max. Password Age:	
	Force Logoff:		
	Lockout Threshold:	-
	Lockout Observation Window:	-
	Lockout Duration:	-
	Password Properties:	-
	Min. Password Length:	-
	Password History Length:	-
	Machine Account Quota:	7
	Mixed Domain Mode:	24
	Domain Behavior Version:	-
	OEM Information:	-

Additional Information:
	Privileges:		-
```

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### **References**

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4739](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4739)
2. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)
3. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)
