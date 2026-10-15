# Front end + FastAPI (what was added)

A simple web page for trying the scanner, connected to the existing `scan()` function through a FastAPI backend. No scanner logic was changed.

## Files added

| File | Purpose |
|---|---|
| `llm_scanner/api.py` | FastAPI app. `POST /scan` runs `scan(text)` and returns the `Risk` result as JSON. `GET /` serves the page. |
| `llm_scanner/static/index.html` | Single-file front end (plain HTML/CSS/JS, no build step). Text box, Scan button, colored risk level, list of findings. |
| `tests/test_api.py` | 3 tests: injection is flagged, missing `text` returns 422, home page is served. |
| `requirements.txt` | Added `fastapi`, `uvicorn`, `httpx` (`httpx` is only needed by the tests). |

## How it connects

```
browser (index.html)  --POST /scan {"text": "..."}-->  api.py  -->  scanner.scan()
                      <--------- Risk as JSON --------
```

The response uses the existing `Risk` model (`score`, `level`, `detections`, `category_scores`, `truncated`), so the page and the CLI `--json` output show the same data.

## Run it

```
.venv\Scripts\python -m uvicorn llm_scanner.api:app --reload
```

Open http://127.0.0.1:8000.

## Status

- Full test suite: 262 passed (includes the 3 new API tests).
- The page has not yet been checked visually in a browser.
- Not covered yet: authentication, rate limiting, CORS (the page is served from the same origin, so CORS is not needed for it).
