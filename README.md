# Overview

The **Active Directory Event Detection Guide** is a comprehensive resource developed to enhance the detection and monitoring of critical Active Directory (AD) events using Splunk. This guide is intended for **cybersecurity professionals, system administrators, and incident responders** aiming to boost visibility into AD activities and strengthen their organization's security posture.

#### Key Objectives

* **Simulate and Document AD Events**\
  Conduct simulations of various AD events—including user account actions, group policy modifications, and privilege assignments—to observe log generation and categorization.
* **Analyze Event Logs**\
  Capture logs for each event and identify key details, including event IDs and log sources, to map events to relevant Splunk categories.
* **Develop Splunk Use Cases for Detection**\
  Create use cases in Splunk with custom detection rules, queries, and alerts to monitor each event type in real-time.

{% hint style="warning" %}
Please keep a note that the documentation was prepared based on Win2008, Win2012R2, Win2016 and Win10+, Win2019
{% endhint %}

***

#### Tools and Methodology

This guide leverages a combination of:

* **Automation Tools**: Using Caldera for selected simulations.
* **Command Line**: Executing PowerShell and Windows CLI commands for event generation.
* **Graphical Interface**: Performing manual operations through the Windows GUI where needed.

Each use case provides:

* **Event Execution Steps**: Detailed instructions for event simulation.
* **Log Analysis**: Identification of log categories and event IDs associated with each activity.
* **Splunk Detection Guidelines**: Configuration of queries, alerts, and thresholds within Splunk to support continuous monitoring.

***

Following this guide will empower anyone to:

1. **Enhance AD Visibility** by detecting and analyzing key security events.
2. **Establish Proactive Monitoring** with custom detection strategies.
3. **Strengthen Incident Response** by promptly identifying and responding to critical AD changes.

By implementing these use cases, anyone can gain hands-on experience with AD monitoring, improve its overall security stance, and ensure adherence to best practices in AD event detection.
