---
layout: default
title: Ultra Quickstart
permalink: /ultra-quickstart/
tagline: "Copy-paste one file and trigger a live trap from your terminal in under 2 minutes."
---

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
  <button class="lang-btn" onclick="switchLang('go')">Go</button>
</div>

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
ts.trap("/admin/config").methods("GET")
    .respond({ status: 200, body: { debug: true } });

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
<div class="lang-content" data-lang="go" markdown="1">

### 1. Save as `main.go`

```go
package main

import (
    "net/http"
    "sync"

    "github.com/gin-gonic/gin"
    trappsec "github.com/trappsec-dev/trappsec/packages/go/gin"
)

var (
    mu     sync.Mutex
    userDB = map[string]string{"username": "guest"}
)

func main() {
    r := gin.New()
    app := trappsec.InstallSentry(r, "DemoApp", "Dev")

    app.IdentifyUser(func(req any) *trappsec.AuthContext {
        c := req.(*gin.Context)
        if uid := c.GetHeader("x-user-id"); uid != "" {
            return &trappsec.AuthContext{User: uid, Role: "user"}
        }
        return nil
    })

    // 1. Decoy Route (Trap)
    app.Trap("/admin/config").Methods("GET").Respond(trappsec.ResponseConfig{
        Status: 200, Body: map[string]any{"debug": true},
    })

    // 2. Honey Field (Watch)
    app.Watch("/profile").Body("is_admin", trappsec.NoDefault, "PrivEsc")

    app.GET("/profile", func(c *gin.Context) {
        mu.Lock()
        u := userDB["username"]
        mu.Unlock()
        // Bait: Reveal 'is_admin' field to encourage tampering
        c.JSON(http.StatusOK, gin.H{"username": u, "is_admin": false})
    })

    app.POST("/profile", func(c *gin.Context) {
        var body map[string]any
        _ = c.ShouldBindJSON(&body)
        // Regular logic: Update username
        if u, ok := body["username"].(string); ok {
            mu.Lock()
            userDB["username"] = u
            mu.Unlock()
        }
        // 'is_admin' is ignored here, but trappsec sees it!
        mu.Lock()
        u := userDB["username"]
        mu.Unlock()
        c.JSON(http.StatusOK, gin.H{
            "status": "updated",
            "user":   gin.H{"username": u},
        })
    })

    app.Run(":5000")
}
```

### 2. Run

```bash
go mod init demo
go mod tidy
go run main.go
```

### 3. Attack

```bash
# Check Profile (See Bait)
curl http://localhost:5000/profile
# Output: {"is_admin":false,"username":"guest"}

# Trigger Watch (Try to become admin)
curl -X POST http://localhost:5000/profile \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker", "is_admin": true}'

# Trigger Trap (Test alerting)
curl http://localhost:5000/admin/config
```

</div>

<br>

{: .note }
> **Windows Users:** The `curl` command syntax differs for Windows Command Prompt (cmd.exe). Use double quotes for JSON and escape inner quotes:
>
> ```
> curl -X POST http://localhost:5000/profile \
>   -H "Content-Type: application/json" \
>   -d "{\"username\": \"hacker\", \"is_admin\": true}"
> ```

