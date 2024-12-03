# Download String Command Detected

The following analytic detects the use of PowerShell's `DownloadString` method to download files. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because `DownloadString` is commonly used in malicious PowerShell scripts to fetch and execute remote code. If confirmed malicious, this behavior could allow an attacker to download and run arbitrary code, potentially leading to unauthorized access, data exfiltration, or further compromise of the affected system.

### Splunk Query

{% code overflow="wrap" %}
```splunk-spl
index="ad-ps-operational"  EventCode IN(4103,4104) "downloadstring" |eval user=lower(user) 
|search Message="*downloadstring*"|stats values(Message) as message values(User) as user by index sourcetype host EventCode
```
{% endcode %}

### Splunk Log

```
11/04/2024 11:06:54 AM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4104
EventType=3
ComputerName=WIN-3BK7E06Q35B.test.com
User=NOT_TRANSLATED
Sid=S-1-5-21-2889491314-2746541823-3071263440-500
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Warning
RecordNumber=6660
Keywords=None
TaskCategory=Execute a Remote Command
OpCode=On create calls
Message=Creating Scriptblock text (52 of 69):
...........<some_script>

                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }

............<some_script>

ScriptBlock ID: 9141b17a-27a1-4b6b-987e-74874f7a9e3e
Path: C:\Users\Administrator\Downloads\powerview.ps1
```

### Splunk Alert

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Alert Manager Dashboard in Expanded View</p></figcaption></figure>

### References

1. [https://powersploit.readthedocs.io/en/latest/Recon/](https://powersploit.readthedocs.io/en/latest/Recon/)
2. [https://research.splunk.com/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/](https://research.splunk.com/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/)
