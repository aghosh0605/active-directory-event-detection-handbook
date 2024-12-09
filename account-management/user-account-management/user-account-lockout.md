# User Account Lockout

### Event Description

* **Event ID 4740**: This event is logged when a user account is locked out. It includes details about the account that was locked, the source machine that triggered the lockout, and the domain controller processing the event. Monitoring this event is critical to detect and respond to potential brute-force attacks or unusual account lockout activity.

***

### Use Case Implementation

{% tabs %}
{% tab title="GUI" %}
**Enable or Modify Account Lockout Policy:**

* Open **Local Group Policy Editor** (`gpedit.msc`) or **Group Policy Management** for domain policies.
* Navigate to **Computer Configuration** > **Windows Settings** > **Security Settings** > **Account Policies** > **Account Lockout Policy**.
* Set appropriate values for:
  * **Account lockout threshold**: Number of failed attempts before lockout.
  * **Account lockout duration**: Duration the account remains locked.
  * **Reset account lockout counter after**: Time to reset the failed attempts counter.

**Simulating Account Lockout:**

* Attempt to log in with an incorrect password multiple times (default threshold is typically 5 attempts).
* Ensure the account lockout policy is enabled in the domain or local security policy.
* Once the account is locked, check **Event Viewer** for the account lockout event.
{% endtab %}

{% tab title="CMD" %}
* Open **Command Prompt**.
*   Use the `net accounts` command to update the policy:

    ```batch
    net accounts /minpwlen:8 /maxpwage:90 /lockoutthreshold:5 /lockoutduration:30
    ```

    * `minpwlen`: Minimum password length.
    * `maxpwage`: Maximum password age (in days).
    * `lockoutthreshold`: Number of failed attempts before lockout.
    * `lockoutduration`: Duration of lockout (in minutes).
*   Run the below command to check the password policy currently set:

    ```batch
    net accounts
    ```

    This displays details about the password policy, including:

    * Minimum password length
    * Password history requirements
    * Lockout threshold and duration
*   Use the `runas` command to attempt a login with incorrect credentials repeatedly:

    ```batch
    runas /user:DOMAIN\UserName cmd
    ```

    * Replace `DOMAIN\UserName` with the target username.
    * Enter an incorrect password multiple times until the account is locked.
{% endtab %}

{% tab title="Powershell" %}
* Open **PowerShell**.
*   Use the following command to modify the policy:

    ```powershell
    Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -MinPasswordLength 8
    ```

    * **Parameters**:
      * `-ComplexityEnabled $true`: Enforce password complexity.
      * `-LockoutThreshold 5`: Number of failed login attempts before lockout.
      * `-LockoutDuration`: Time span of the lockout.
      * `-MinPasswordLength`: Minimum password length.
*   Run the below command to check the password policy currently set:

    ```powershell
    Get-ADDefaultDomainPasswordPolicy
    ```

    * This retrieves the password policy for the domain.
    * You need the Active Directory module installed.
*   Use the following loop to simulate failed logins:

    ```powershell
    for ($i = 1; $i -le 10; $i++) {
        Start-Process -FilePath "runas" -ArgumentList "/user:DOMAIN\UserName cmd" | Out-Null
        Start-Sleep -Milliseconds 500 # Optional delay between attempts
    }

    ```

    * Replace `target_system` with the hostname or IP address of the target.
    * Replace `DOMAIN\UserName` with the username to simulate failed attempts.

    After exceeding the account lockout threshold, the event will be logged.
{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

> Audit Success 06-12-2024 13:43:08 Microsoft Windows security auditing. 4740 User Account Management

***

### Splunk Queries

Below is the basic example of Multiple Account Lockout from Single Host:

{% code overflow="wrap" %}
```splunk-spl
index=ad-test  EventCode=4740 
| bin span=30m _time
| stats dc(user) AS UserCount values(user) AS Users by _time index EventCode host ComputerName sourcetype
| where UserCount>2
```
{% endcode %}

***

### Splunk Logs

```
12/06/2024 01:43:08 PM
LogName=Security
EventCode=4740
EventType=0
ComputerName=WIN-3BK7E06Q35B.test.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=163058
Keywords=Audit Success
TaskCategory=User Account Management
OpCode=Info
Message=A user account was locked out.

Subject:
	Security ID:		S-1-5-18
	Account Name:		WIN-3BK7E06Q35B$
	Account Domain:		TEST
	Logon ID:		0x3E7

Account That Was Locked Out:
	Security ID:		S-1-5-21-2889491314-2746541823-3071263440-1120
	Account Name:		lockuser3

Additional Information:
	Caller Computer Name:
```

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740)
2. [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\))
3. [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.4](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.4)
4. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)
5. [https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)

***
