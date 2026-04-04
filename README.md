# Privacy Sentinel

Privacy Sentinel is a cybersecurity-focused privacy monitoring project with two parts:

- Browser extension (Chrome/Edge, Manifest V3) that scans cookies for the active website.
- Python backend API that analyzes tracking behavior, assigns a privacy risk score, and generates downloadable reports.

## Features

- Real-time cookie scan from current tab
- First-party vs third-party cookie detection
- Security attribute checks (`Secure`, `HttpOnly`, `SameSite`)
- Tracking pattern analysis (known ad-tech domains and naming indicators)
- Page privacy signal detection for microphone, camera, and location usage
- Third-party data transfer alerts based on page network activity
- Risk scoring with severity (`low`, `medium`, `high`, `critical`)
- Privacy recommendations (history-aware and freshness-oriented)
- JSON report history, single-report retrieval, and report deletion
- Settings page export for full report download

## Project Structure

```
backend/
  app/
    analyzer.py
    main.py
    models.py
  tests/
    test_analyzer.py
  requirements.txt

browser-extension/
  manifest.json
  background.js
  popup.html
  popup.css
  popup.js
  options.html
  options.js
```

## Backend Setup

1. Open a terminal in `backend`.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Start API server:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Extension Setup

1. Open browser extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
2. Enable Developer mode.
3. Click Load unpacked and select `browser-extension`.
4. Pin Privacy Sentinel.
5. Open any website and click Scan Current Site.

## API Endpoints

- `GET /health`
- `POST /analyze`
- `GET /report/{report_id}`
- `DELETE /report/{report_id}`
- `GET /reports`

## Notes

- The extension can only inspect cookies available through browser APIs.
- Detection is heuristic-based and intended for defensive awareness, not legal compliance guarantees.

## Testing

From `backend`:

```bash
pytest
```

Performance-focused check:

```bash
pytest -k performance
```
