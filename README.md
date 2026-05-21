# Password Checker

Check if a password appears in known wordlists or the [Have I Been Pwned](https://haveibeenpwned.com/) breach database. For legitimate security awareness only.

## Features

- Web UI with **live REST API** (no page reload)
- Fast lookups: SQLite index, bloom filters, optional [ripgrep](https://github.com/BurntSushi/ripgrep)
- HIBP k-anonymity API, local wordlists, hash lists, optional online lists
- Password variants (leet, normalize), strength score, optional zxcvbn

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

**First-time speed boost:**

```bash
python app.py --build-index lists
python app.py --build-index hashes
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Health & stats |
| POST | `/api/check` | Check password (JSON) |

```bash
curl -X POST http://127.0.0.1:5000/api/check ^
  -H "Content-Type: application/json" ^
  -d "{\"password\":\"test\",\"hibp\":true,\"local\":true}"
```

## CLI

```bash
python app.py --check "mypassword"
python app.py --bulk passwords.txt
python app.py --clear-cache
```

## Project layout

```
app.py          # Flask UI + API
scanner.py      # Scan logic
indexer.py      # SQLite / bloom / ripgrep
config.yaml     # Settings
lists/          # Wordlist files (.txt, .gz)
hashes/         # Hash list files
templates/      # HTML
static/         # CSS + JS
tests/          # pytest
```

## Configuration

Edit `config.yaml`. For production, set:

```bash
set FLASK_SECRET_KEY=your-long-random-secret
```

See `.env.example`.

## Publishing / sharing this folder

**Include:** all `.py`, `config.yaml`, `requirements.txt`, `templates/`, `static/`, `tests/`, `lists/.gitkeep`, `hashes/.gitkeep`, `LICENSE`, `README.md`, `run.bat`, `prebuild.bat`

**Do not upload:** `.venv/`, `.cache/`, `.env`, real password lists (large `.txt` files), personal bulk reports

## Tests

```bash
pytest tests/
```

## Disclaimer

Use only on passwords you are allowed to test. Not for unauthorized access or criminal activity.

## License

MIT — see [LICENSE](LICENSE).
