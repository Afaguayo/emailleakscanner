# 🛡️ Email Leak Scanner

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://github.com/Afaguayo/emailleakscanner/actions/workflows/build.yml/badge.svg)

Check whether an email address shows up in known data breaches, see **what** leaked (passwords, phone numbers, addresses…), and get a clear list of what to do about it. Desktop app for Windows and macOS, plus a command-line tool.

## ⬇️ Download

Grab the latest build from **[Releases](https://github.com/Afaguayo/emailleakscanner/releases/latest)**:

- **Windows:** `EmailLeakScanner.exe`. Double-click to run. SmartScreen may warn because the app isn't code-signed: click *More info → Run anyway*.
- **macOS:** `EmailLeakScanner-macOS.zip`. Unzip, then right-click the app → *Open* the first time (it isn't notarized).

## 🔎 What it checks

| Source | What you get | Key needed? |
|---|---|---|
| [XposedOrNot](https://xposedornot.com) | Breach list with dates, descriptions, exposed data types and a risk score | No |
| [LeakCheck](https://leakcheck.io) | Breach sources and the kinds of fields leaked | No |
| [HaveIBeenPwned](https://haveibeenpwned.com) | Verified breach list | Yes, [paid key](https://haveibeenpwned.com/API/Key) (optional) |
| DuckDuckGo | Public web pages whose text contains the address | No |
| [Pwned Passwords](https://haveibeenpwned.com/Passwords) | How often a password appears in leaks | No |

The same breach reported by several services is merged into one entry (matched by name or domain), so the count isn't inflated.

**Password check privacy:** the password is hashed (SHA-1) on your computer and only the first 5 characters of the hash are sent ([k-anonymity](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity)). The password itself never leaves your machine.

## ✨ Features

- Risk score (0–100) with plain-language advice: change reused passwords, turn on 2FA, credit freeze if IDs leaked…
- Exposed data at a glance: passwords in red, sensitive data (IDs, phone, address, date of birth) in orange
- Filterable breach list (by site or data type, or "only with passwords")
- Save reports as text or JSON
- All sources run in parallel; if one is down the rest still report
- CLI with batch scanning from a file and JSON output for scripts

## 🖥️ Run from source

Python 3.9+. The scanner uses only the standard library; the desktop window needs `pywebview`.

```bash
git clone https://github.com/Afaguayo/emailleakscanner.git
cd emailleakscanner
pip install -r requirements.txt   # only needed for the desktop window
python gui.py                     # desktop app (falls back to your browser without pywebview)
```

### Command line

```bash
python emailleakscanner.py                          # interactive
python emailleakscanner.py you@example.com          # scan one or more addresses
python emailleakscanner.py -f emails.txt --save reports --format json
python emailleakscanner.py you@example.com --json   # machine-readable output
python emailleakscanner.py you@example.com --all    # list every breach, not just the newest 25
python emailleakscanner.py --password               # check a password (hidden prompt)
```

### HaveIBeenPwned key (optional)

Any of these works:
- set the `HIBP_API_KEY` environment variable
- put `HIBP_API_KEY=your_key` in a `.env` file next to the script
- paste it into **Settings** in the desktop app (saved in `~/.emailleakscanner.json`)
- pass `--hibp-key` on the command line

## 🧪 Tests and building

```bash
python -m unittest -v                              # offline tests, no network needed
pip install -r requirements.txt pyinstaller
python build.py                                    # builds dist/EmailLeakScanner(.exe/.app) for your OS
```

Pushing a `v*` tag runs [the workflow](.github/workflows/build.yml), which tests, builds the Windows `.exe` and the macOS app, and attaches them to a GitHub release.

## ⚠️ Legal

For personal and educational use. Only scan addresses you own or have permission to check. Results come from third-party services and can be incomplete. "Not found" doesn't guarantee an address was never leaked.

## 📜 License

[MIT](LICENSE)
