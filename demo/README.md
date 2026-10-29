# Local demo

A one-page UI over the scanner: paste a tool description, a SKILL.md
body, or server source and get the live verdict.

```bash
pip install fastapi uvicorn
uvicorn demo.app:app --reload   # from the repo root
# open http://127.0.0.1:8000/
```

Stack shape follows the portfolio demo standard (React front end,
FastAPI backend). Hosted deployment is a separate, later step.
