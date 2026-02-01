## **trappsec** > deception as a developer tool
trappsec is an open-source application-layer deception framework that helps developers catch attackers probing their APIs.

### Core Concepts
> **decoy routes** are ghost endpoints that exist solely to catch unauthorized probing. If someone hits a decoy, they are anything but a regular user. Decoy routes blend into your application by responding with configurable responses that look like they are part of your real API.

> **honey fields** are invisible parameters added to legitimate routes. They catch attackers attempting to manipulate seemingly sensitive and lucrative fields. Honey fields are invisible to users but visible to attackers probing your API.

> **attribution** of alerts to specific identities and ip addresses is enabled through the framework hooks. decoy routes and honey fields can also be linked to an intent. Put together, you get alerts that security teams can respond to quickly and more effectively.

### Alerts & Integrations
Track alerts in your logs/opentelemetry or send them to your SIEM, Slack or any incident response tool or workflow that supports webhooks. Turn an attacker’s reconnaissance phase into your most reliable stream of security telemetry.