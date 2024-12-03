# ACL Modified by AdminSDHolder

## Group Type Changed Detection

### Event Description

* **Event ID 4780**: This event, 4780, is logged whenever Windows modifies the ACL of a member of Domain Admins or Administrators to match the standard ACL in the AdminSDHolder object. AdminSDHolder defines a stricter ACL to protect members of admin groups from being modified and taken over by other privileged users like Account Operators.

{% hint style="info" %}
You will also see event ID [4738](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4738) informing you of the same information.
{% endhint %}

***

### Use Case Implementation

#### Steps to Simulate and Capture Logs

{% tabs %}
{% tab title="GUI" %}

{% endtab %}

{% tab title="CMD" %}

{% endtab %}

{% tab title="Powershell" %}

{% endtab %}
{% endtabs %}

***

### Event Viewer Logs

_Attach the exported event logs for Event ID 4780 demonstrating group type changes._

***

### Splunk Queries

> _(Placeholder for Splunk queries; insert your custom detection logic here for monitoring group type change events.)_

***

### Splunk Logs

_Attach relevant Splunk log outputs here, showing detection of group type changes._

***
