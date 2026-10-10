---
layout: default
title: Tuning False Positives
permalink: /tuning/
tagline: "Keep alerts high-signal."
---

A good trappsec deployment produces few events, and every one deserves a look. If you are drowning, work through the following.

## Understand signals vs alerts

*   `alert`: the request had an identified user (`identify_user` returned a `user`). Someone authenticated did something they should not.
*   `signal`: no identified user. Often scanners and bots.

Webhook and Slack handlers send only alerts by default (`alerts_only=true`). Keep it that way for paging and chat; send signals (`alerts_only=false`) to a log index or OpenTelemetry for hunting and trend analysis.

If everything is a signal, check that `identify_user` returns the keys **`user`** and **`role`** (not `id` or `user_id`) and that it runs after your auth middleware.

## Make traps hard to hit by accident

*   Never reference a trap from your own UI, sitemap, or monitoring. Health checks, uptime probes, vulnerability scanners and link checkers must not hit decoys. Exclude them by IP, or filter on `user_agent` in your receiver.
*   Do not use paths that legitimate tooling probes by default (`/robots.txt`, `/.well-known/*`, `/health`).
*   Bait only where an authenticated attacker would find it: client-side references, API specs for internal users, documentation.

## Choose honey fields carefully

*   Watch fields your legitimate clients never send, or send with a fixed value. Use `default=` for fields the UI echoes back unchanged (read-only attributes).
*   Remember [value matching](/events/#value-matching): the form value `"false"` equals default `false`. Case differs: `"False"` does not.
*   A repeated parameter is a violation unless every occurrence equals the default. If a client library legitimately repeats a field, it will alert; fix the client or drop the watch.
*   Watching only the fields that matter keeps volume down. Do not watch common names like `id` or `name`.
*   In Go, JSON keys match case-insensitively; avoid watching a name that differs from a real field only by case.

## Use intent for triage

Give every trap and field an `intent` (`PrivEsc`, `Recon`, ...). Route different intents to different channels or severities in your receiver.

## Reduce noise at the receiver

*   Deduplicate on `ip` + `path` + `user` over a short window.
*   Use the [webhook `template`](/api/#add_webhook) to forward only the fields you need.
*   Allow-list known pentest or scanner IPs; remember `ip` is only accurate if proxies are configured ([Production](/production/#proxies-and-client-ip)).
*   Treat an authenticated hit on a trap as high severity, an unauthenticated one as informational.

## Verify before you trust

Use the e2e examples or your own tests: hit each trap unauthenticated and authenticated, send each honey field with the default and a violating value, and confirm only violations alert.
