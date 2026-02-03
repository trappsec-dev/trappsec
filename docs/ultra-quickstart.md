---
layout: default
title: Ultra Quickstart
nav_order: 5
permalink: /ultra-quickstart/
---

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
</div>

# Ultra Quickstart

{: .warning }
> This example is designed for **quick copy-paste local testing only**. For proper integration, please consult the [Getting Started](/getting-started/) guide.

Copy-paste this into a file to see trappsec in action immediately.

<div class="lang-content" data-lang="python" markdown="1">

### 1. Save as `app.py`

```python
from flask import Flask, request
import trappsec

app = Flask(__name__)
# Mock Database
user_db = {"username": "guest"}

ts = trappsec.Sentry(app, "DemoApp", "Dev")
ts.identify_user(lambda r: {"user": user_db["username"]})

# 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond(200, {"debug": True})

# 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", intent="PrivEsc")

@app.route("/profile", methods=["GET"])
def get_profile():
    # Bait: Reveal 'is_admin' field to encourage tampering
    return {"username": user_db["username"], "is_admin": False}

@app.route("/profile", methods=["POST"])
def update_profile():
    # Regular logic: Update username
    user_db["username"] = request.json.get("username", user_db["username"])
    # 'is_admin' is ignored here, but trappsec sees it!
    return {"status": "updated", "user": user_db}

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
# Check Profile (See Bait)
curl http://localhost:5000/profile
# Output: {"username": "guest", "is_admin": false}

# Trigger Watch (Try to become admin)
curl -X POST http://localhost:5000/profile \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker", "is_admin": true}'

# Trigger Trap (Test alerting)
curl http://localhost:5000/admin/config
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

### 1. Save as `app.js`

```javascript
const express = require('express');
const { Sentry } = require('trappsec');

const app = express();
app.use(express.json());

// Mock Database
let userDb = { username: "guest" };

const ts = new Sentry(app, "DemoApp", "Dev");
ts.identify_user((req) => ({ user: userDb.username }));

// 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond({ status: 200, body: { debug: true } });

// 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", { intent: "PrivEsc" });

app.get("/profile", (req, res) => {
    // Bait: Reveal 'is_admin' field
    res.json({ ...userDb, is_admin: false });
});

app.post("/profile", (req, res) => {
    // Regular logic: Update username
    if (req.body.username) userDb.username = req.body.username;
    // 'is_admin' is ignored here, but trappsec sees it!
    res.json({ status: "updated", user: userDb });
});

app.listen(5000, () => console.log("Running on port 3000"));
```

### 2. Run

```bash
npm install express trappsec
node app.js
```

### 3. Attack

```bash
# Check Profile (See Bait)
curl http://localhost:5000/profile
# Output: {"username": "guest", "is_admin": false}

# Trigger Watch (Try to become admin)
curl -X POST http://localhost:5000/profile \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker", "is_admin": true}'

# Trigger Trap (Test alerting)
curl http://localhost:5000/admin/config
```

</div>
