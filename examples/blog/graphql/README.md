# Authenticated GraphQL Decoy (Flask + trappsec)

Minimal Flask app demonstrating:

- JWT authentication (HS256)
- A protected `/me` endpoint
- A decoy `/graphql` endpoint using **trappsec**
- Identity attribution for authenticated trap hits

The `/graphql` route is **not a real GraphQL server**.  
It is a deception endpoint designed to detect reconnaissance.

---

## Run

```bash
uv run main.py
```

OR

```bash
pip install flask pyjwt trappsec graphql-core
python main.py
```

---

## Verify
to login and grab an access token
```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password"}'
```

to trigger a decoy using graphql introspection. replace token from above
```bash
curl -X POST http://127.0.0.1:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"{ __schema { types { name } } }"}'
```
