# Kerberos Authentication Service

**Enable Kerberos Logging (if not already enabled):**

* Open the **Group Policy Management Editor**.
* Navigate to **Computer Configuration** > **Windows Settings** > **Security Settings** > **Advanced Audit Policy Configuration** > **Account Logon**.
* Enable **Audit Kerberos Authentication Service** for success and failure.

At last, run `gpupdate /force` in cmd or powershell to enforce the policy as soon as possible.
