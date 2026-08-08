# Sentry — Security Alert Dashboard

**Sentry** is a real-time Security Alert Dashboard prototype designed for Security Operations Centers (SOC). It ingests authentication log telemetry, detects brute-force attack clusters, and visualizes suspicious activity so security administrators can spot threats at a glance rather than analyzing raw log files.

---

## Changes made for the final review (Aug 10)

1. **Removed all internet dependencies.** Chart.js and all fonts (Space
   Grotesk, Inter, IBM Plex Mono) are now bundled locally under
   `static/vendor/`, instead of loading from Google Fonts / a CDN. The
   dashboard now works fully offline — important since review rooms often
   have unreliable wifi.
2. **Debug mode is off by default.** Prevents the dev server from
   randomly restarting mid-demo. Set `FLASK_DEBUG=1` if you need the
   auto-reloader while actively developing.
3. **Added `/api/export-report`** and an **Export Report** button on the
   dashboard. This downloads a JSON file with the current summary stats,
   flagged IPs, and sample alerts — a concrete "results" artifact you can
   show the panel beyond just the live demo.
4. Removed unused scaffold files (a leftover React/Vite template AI
   Studio generates by default) that had nothing to do with this Flask
   project.

---

## New in this version: Auth, Live Demo, Excel Export, Restyle (Aug 8)

### 1. Authentication — Security Department only
The dashboard (`/`) and all `/api/*` routes are now behind a login screen.
Demo credentials for the review:

| Username | Password | Name |
|---|---|---|
| `admin` | `Sentry@123` | Security Admin |
| `sk.parveen` | `Sentry@123` | SK Parveen |
| `r.sivateja` | `Sentry@123` | R Siva Teja |

Accounts live in `auth.py` — add more teammates there if needed. Passwords
are hashed with Werkzeug's `generate_password_hash`, sessions are signed
cookies via Flask's built-in session support.

### 2. Live demo: intentionally fail a login
`/system-login` is a **separate, public page** representing the system
Sentry is monitoring (not the dashboard itself). Any attempt made there is
logged as a real event:
- A single wrong password bumps the Failed Attempts KPI and timeline chart
  immediately, but won't get flagged as "suspicious" on its own — Sentry
  only flags an IP after 5+ failed attempts in 15 minutes, by design.
- Use the **"Trigger Detection Now"** button on that page for the full
  live effect: it fires 6 rapid failed attempts and the IP gets flagged
  immediately — watch the Live Alert Feed, Flagged IPs table, and status
  pill all update in real time on the dashboard.

Known demo users (password `Demo@123` for a successful login): `admin`,
`rsteja`, `bhagya.s`, `meghana.t`, `geethika.v`, `parveen.sk`, `svc_backup`,
`root`, `j.rajendra`, `analyst01`.

### 3. Excel report export (with time range)
Click **Download Excel Report** on the dashboard. Optionally set a From/To
range first — leave both blank to export everything. The file has two
sheets:
- **Login Events** — every event with Timestamp, Username, IP Address,
  Location, Status, Reason, and whether it was Flagged Suspicious.
- **Summary** — totals, the detection rule, and a table of flagged IPs.

A JSON version (`/api/export-report`) is still available too, also
supports `?start=` and `?end=` query params.

### 4. Visual refresh
- Single sans-serif font (Inter) throughout, replacing the previous
  Space Grotesk + IBM Plex Mono pairing.
- Buttons are now flat, single-color, medium-sized, with simple rounded
  corners (10px) — no gradients or glow shadows.

---

## 🛠️ Project Structure

```
.
├── app.py              # Flask app rendering dashboard & handling API endpoints
├── data_generator.py   # Generates realistic login telemetry & attack bursts
├── analyzer.py         # Detection engine analyzing sliding time-window threat signatures
├── templates/
│   └── index.html      # Security Operations Console HTML dashboard
├── static/
│   ├── css/
│   │   └── style.css   # Dark console styling (Space Grotesk, Inter, IBM Plex Mono)
│   └── js/
│       └── dashboard.js# Client telemetry fetcher, Chart.js, and live feed updater
├── requirements.txt    # Python dependencies (Flask, Flask-CORS)
└── README.md           # Project documentation
```

---

## 🛡️ Brute-Force Detection Logic

The detection engine in `analyzer.py` flags suspicious IP activity using the following sliding window rule:

1. **Rule**: Any IP address with **5 or more failed login attempts within a 15-minute sliding window** is flagged as suspicious.
2. **Risk Categorization**:
   - **CRITICAL**: Flagged IPs with **12 or more** total failed attempts (e.g. rapid automated brute-force attacks).
   - **HIGH**: Flagged IPs with **5 to 11** failed attempts.
3. **Telemetry Indicators**:
   - Total events & fail percentage
   - Targeted user list per suspicious IP
   - Earliest and latest attack timestamps
   - Hourly 24-hour timeline buckets for login activity charts

---

## 🚀 Running the App Locally

### Prerequisites
- Python 3.10+
- `pip` package manager

### Steps
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Flask application:
   ```bash
   python app.py
   ```
3. Open your browser and visit:
   ```
   http://localhost:3000
   ```

---

## 📡 API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Renders the main Sentry Security Operations Console dashboard |
| `GET` | `/api/summary` | Returns overall telemetry stats (total events, fails, successes, threat count) |
| `GET` | `/api/timeline` | Returns 24-hour hourly buckets for successful vs. failed logins |
| `GET` | `/api/suspicious-ips` | Returns list of flagged IPs with risk levels, country, and target metadata |
| `GET` | `/api/alerts` | Returns time-ordered stream of failed login alerts from flagged IPs |
| `POST` | `/api/simulate-attack` | Injects a live brute-force burst (10-15 failed attempts) into the event log |

---

## ⚡ Live Attack Simulation
To demonstrate live threat detection, click the **"Simulate Attack"** button in the top right header. This invokes `POST /api/simulate-attack`, injecting a fresh cluster of failed login attempts from a new foreign IP into the in-memory telemetry stream. The dashboard automatically updates all KPI readouts, the timeline chart, the suspicious IP table, and the live terminal alert feed in real time.
