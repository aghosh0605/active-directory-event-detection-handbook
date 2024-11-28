# Kerberos Pre-Auth Discovery/Disabled commands detected

### Description

AS-REP roasting is a technique that allows retrieving password hashes for users that have `Do not require Kerberos preauthentication` property selected.

![](https://www.ired.team/~gitbook/image?url=https%3A%2F%2F386337598-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fassets%252F-LFEMnER3fywgFHoroYn%252F-L_nj7h01rJKzhElx_RC%252F-L_njEkL2a_oSCa1g0H9%252FScreenshot%2520from%25202019-03-12%252021-08-33.png%3Falt%3Dmedia%26token%3Ddc08b9a5-1cae-4762-a6a0-773735227aad\&width=768\&dpr=4\&quality=100\&sign=3d1becf6\&sv=1)

### Use Case Implementation

```powershell
Set-ADAccountControl -Identity testuser -DoesNotRequirePreAuth $true
```

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index="ad-ps-operational"  EventCode IN(4103,4104) (("*Get-ADUser*" AND "*DoesNotRequirePreAuth*") OR ("*Set-ADAccountControl*" AND "*DoesNotRequirePreAuth $true*"))
|table index sourcetype host EventCode Message |rename EventCode as event_code Message as message
```
{% endcode %}

### Splunk Log

{% tabs %}
{% tab title="4103" %}
```
11/28/2024 11:25:08 AM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4103
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Information
RecordNumber=9406
Keywords=None
TaskCategory=Executing Pipeline
OpCode=To be used when operation is just executing a method
Message=CommandInvocation(Get-ADUser): "Get-ADUser"
ParameterBinding(Get-ADUser): name="Filter"; value="DoesNotRequirePreAuth -eq $true"


Context:
        Severity = Informational
        Host Name = Windows PowerShell ISE Host
        Host Version = 5.1.20348.558
        Host ID = eb295bdd-fe05-4090-82d0-b42921fcf826
        Host Application = C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe
        Engine Version = 5.1.20348.558
        Runspace ID = 3c871cb7-9394-4983-8fa9-c1aab77302b9
        Pipeline ID = 74
        Command Name = Get-ADUser
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 118
        User = TEST\administrator
        Connected User = 
        Shell ID = Microsoft.PowerShell


User Data:
```
{% endtab %}

{% tab title="4104" %}
```
11/28/2024 11:58:09 AM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4104
EventType=5
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Verbose
RecordNumber=9516
Keywords=None
TaskCategory=Execute a Remote Command
OpCode=On create calls
Message=Creating Scriptblock text (1 of 1):
Set-ADAccountControl -Identity testuser -DoesNotRequirePreAuth $true

ScriptBlock ID: 20a8965a-ce1c-4e21-a8ec-f75e97c89897
Path:
```
{% endtab %}
{% endtabs %}

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
