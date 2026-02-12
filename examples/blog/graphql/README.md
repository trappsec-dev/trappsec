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
