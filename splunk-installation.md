# Splunk Installation

1. Please follow the official docs from Splunk to **install Splunk Enterprise**. Get it [here](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux).
2. After the Splunk Enterprise is installed, we can install Windows universal forwarder in the AD DC to get logs from it. Follow the [guide](https://docs.splunk.com/Documentation/Forwarder/9.3.2/Forwarder/InstallaWindowsuniversalforwarderfromaninstaller) to **install Windows Universal Forwarder** in Windows.
3. Set up a **Receiver** inside **Forwarding and Receiving** for Splunk Enterprise with the following guide [here](https://docs.splunk.com/Documentation/Forwarder/8.2.6/Forwarder/Enableareceiver).
4. Now we can configure the `inputs.conf` of Windows universal forwarder to get the logs accordingly. The default path for `inputs.conf` is **$SPLUNK\_HOME/etc/system/local** (Create the file if it is not present)**.** Paste the below configuration in that file.

```bash
# Windows platform-specific input processor.
[WinEventLog://Application]
disabled = 0 
[WinEventLog://Security]
disabled = 0 
[WinEventLog://System]
disabled = 0 

# These are required for AD-DC
[WinEventLog://DNS Server]
disabled = 0
[WinEventLog://Directory Service]
disabled = 0
[WinEventLog://File Replication Service]
disabled = 0

# This is required for Powershell logging
[WinEventLog://Windows PowerShell]
disabled = 0
index=ad-powershell # Get it in a different index
```

After that restart the Windows Universal Forwarder to apply the changed settings. Go to **$SPLUNK\_HOME/bin** and run a CMD terminal. Run `./splunk.exe restart` to restart the forwarder.

4. Setup the **Forward management** in the Splunk Enterprise Settings.
   1. Set up a server class in Splunk Forward Management. Follow the guide [here](https://docs.splunk.com/Documentation/MSExchange/4.0.4/DeployMSX/Setupadeploymentserver).
   2. Add the Windows universal forwarder into the server class. Follow the guide [here](https://docs.splunk.com/Documentation/MSExchange/4.0.4/DeployMSX/Addtheuniversalforwardertotheserverclass).
5. The last step is to **Add the Forwarder** to the **Add Data** section in Settings inside Splunk Enterprise. (**Optional**- Needed if the index is not mentioned in the **inputs.conf**)

### References

1. [https://lantern.splunk.com/Security/Product\_Tips/Enterprise\_Security/Configuring\_Windows\_security\_audit\_policies\_for\_Enterprise\_Security\_visibility](https://lantern.splunk.com/Security/Product\_Tips/Enterprise\_Security/Configuring\_Windows\_security\_audit\_policies\_for\_Enterprise\_Security\_visibility)
2. [https://docs.splunk.com/Documentation/Splunk/9.3.2/Data/MonitorWindowseventlogdata](https://docs.splunk.com/Documentation/Splunk/9.3.2/Data/MonitorWindowseventlogdata)
3. [https://docs.splunk.com/Documentation/Forwarder/9.3.2/Forwarder/Installtheuniversalforwardersoftware](https://docs.splunk.com/Documentation/Forwarder/9.3.2/Forwarder/Installtheuniversalforwardersoftware)
4.
