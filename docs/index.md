---
layout: default
title: Introduction
nav_order: 1
---

# **turn apps into traps**

## Trappsec is an open-source application-layer deception framework that helps developers catch attackers probing their APIs.

<img src="./assets/images/trappsec-flow.webp" width="70%" alt="trappsec flow">


## 👻 **decoy routes**
"Ghost" endpoints that exist solely to catch unauthorized probing. If someone hits a decoy, they are anything but a regular user. Decoy routes blend into your application by responding with configurable responses that look like they are part of your real API.

## 🍯 **honey fields**
Invisible parameters added to legitimate routes. They catch attackers attempting to manipulate seemingly sensitive and lucrative fields. Honey fields are invisible to users but visible to attackers probing your API.

## 🕵️ **intent & attribution**
Trappsec doesn't just tell you that something happened; it tells you who did it and why. By tying trap hits to pre-defined intent and authenticated user identities, you gain high-confidence attribution for every incident.

## 📢 **alerts & integrations**
Track alerts in your logs/opentelemetry or send them to your SIEM, Slack or any incident response tool or workflow that supports webhooks. Turn an attacker's reconnaissance phase into your most reliable stream of security telemetry.

## 🛡️ **better incident response**
With alerts that include intent and attribution, security teams can respond quickly and more effectively to attacks targetting your critical business applications and APIs.