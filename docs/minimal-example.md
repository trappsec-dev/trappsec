---
layout: default
title: Minimal Example
nav_order: 5
permalink: /minimal-example/
---

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
</div>

# Minimal Example

{: .warning }
> This example is designed for **quick copy-paste local testing only**. 
> It contains hardcoded configurations and does not represent a production-ready setup. 
> For proper integration, please consult the [Getting Started](/getting-started/) guide.

Copy-paste this into a file to see trappsec in action immediately.

<div class="lang-content" data-lang="python" markdown="1">

### 1. Save as `app.py`

```python
from flask import Flask, request
import trappsec

app = Flask(__name__)
ts = trappsec.Sentry(app, "DemoApp", "Dev")
ts.identify_user(lambda r: {"user_id": "guest"})

# 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond(200, {"debug": True})

# 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", intent="PrivEsc")

@app.route("/profile", methods=["POST"])
def update_profile():
    return {"status": "updated"}

if __name__ == "__main__":
    app.run(port=5000)
```

### 2. Run

```bash
pip install flask trappsec
python app.py
```

### 3. Attack

```bash
# Trigger Trap
curl http://localhost:5000/admin/config

# Trigger Watch
curl -X POST http://localhost:5000/profile -H "Content-Type: application/json" -d '{"is_admin": true}'
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

### 1. Save as `app.js`

```javascript
const express = require('express');
const { Sentry } = require('trappsec');

const app = express();
app.use(express.json());

const ts = new Sentry(app, "DemoApp", "Dev");
ts.identify_user((req) => ({ user_id: "guest" }));

// 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond({ status: 200, body: { debug: true } });

// 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", { intent: "PrivEsc" });

app.post("/profile", (req, res) => res.json({ status: "updated" }));

app.listen(3000, () => console.log("Running on port 3000"));
```

### 2. Run

```bash
npm install express trappsec
node app.js
```

### 3. Attack

```bash
# Trigger Trap
curl http://localhost:3000/admin/config

# Trigger Watch
curl -X POST http://localhost:3000/profile -H "Content-Type: application/json" -d '{"is_admin": true}'
```

</div>
