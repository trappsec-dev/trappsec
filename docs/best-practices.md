---
layout: default
title: Best Practices
nav_order: 4
permalink: /best-practices/
---

# Best Practices

### Require Authentication
In an internet that is mostly harmless but increasingly full of people and scanners (mostly scanners) poking things they shouldn't, you don’t want to get buried with noise. Use unauthenticated template responses like (401, Unauthorized) to guide them to probe with authentication.

### Blend In
A good trap should look like a mundane, standard - perhaps even tedious part of your API. If it looks "too good to be true", attackers will ignore it. Design traps to catch people trying to understand or manipulate your business logic.
