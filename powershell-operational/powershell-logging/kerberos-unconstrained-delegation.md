# Kerberos Unconstrained Delegation



### Description

Essentially this looks like this: `User` --- authenticates to ---> `IIS server` ---> authenticates on behalf of the user ---> `DB server`

{% hint style="warning" %}
Any user authentication (i.e CIFS) to the computer with unconstrained delegation enabled on it, will cache that user's TGT in memory, which can later be dumped and reused by an adversary.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption><p>How to set-up</p></figcaption></figure>

### Use Case Implementation

To confirm/find computers on a domain that have unrestricted kerberos delegation property set:

{% code overflow="wrap" %}
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description
```
{% endcode %}

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index="ad-ps-operational"  EventCode IN(4103,4104) (Message="*Get-ADComputer*" AND Message="*TrustedForDelegation*") 
|table index host sourcetype EventCode Message 
|rename EventCode as eventcode ,Message as message
```
{% endcode %}

### Splunk Logs

{% tabs %}
{% tab title="4103" %}
```
11/28/2024 03:40:34 PM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4103
EventType=4
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Information
RecordNumber=9560
Keywords=None
TaskCategory=Executing Pipeline
OpCode=To be used when operation is just executing a method
Message=CommandInvocation(Get-ADComputer): "Get-ADComputer"
ParameterBinding(Get-ADComputer): name="Filter"; value="TrustedForDelegation -eq $true -and primarygroupid -eq 515"
ParameterBinding(Get-ADComputer): name="Properties"; value="trustedfordelegation, serviceprincipalname, description"


Context:
        Severity = Informational
        Host Name = Windows PowerShell ISE Host
        Host Version = 5.1.20348.558
        Host ID = 60a07bf2-7d1a-4792-9654-9af7ca04b696
        Host Application = C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe
        Engine Version = 5.1.20348.558
        Runspace ID = b42132bf-fead-4bfe-b68e-207c3639f640
        Pipeline ID = 10
        Command Name = Get-ADComputer
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 36
        User = TEST\administrator
        Connected User = 
        Shell ID = Microsoft.PowerShell


User Data:
```
{% endtab %}

{% tab title="4104" %}
```
11/28/2024 03:40:31 PM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4104
EventType=5
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Verbose
RecordNumber=9559
Keywords=None
TaskCategory=Execute a Remote Command
OpCode=On create calls
Message=Creating Scriptblock text (1 of 1):
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description

ScriptBlock ID: ef4ea43b-b781-4d2f-a71c-9fde4ce58df9
Path:
```
{% endtab %}
{% endtabs %}

### Splunk Alert



### References

1. [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
