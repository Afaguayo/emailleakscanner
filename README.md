# emailleakscanner
Multi-source email scanner that checks if your email was exposed in breaches or public websites. Uses LeakCheck, HaveIBeenPwned, and Google Search. Free, fast, and easy to use. Built with Python and BeautifulSoup.
# 🛡️ Multi-Source Email Breach and Exposure Scanner

![Python](https://img.shields.io/badge/python-3.7%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

A powerful, lightweight Python tool to check if your email address has been:
- Exposed in known data breaches
- Mentioned publicly on the internet

It uses **free and public sources**:
- 🔎 [LeakCheck.net](https://leakcheck.net)
- 🔎 [HaveIBeenPwned.com](https://haveibeenpwned.com)
- 🔎 [Google Search](https://google.com)

---

## 🚀 Features
- Scan multiple data sources automatically
- Detect exposed email/password combinations
- Search the web for public traces of your email
- No paid API keys required (only free signup for HIBP)
- Secure `.env` file handling for API keys
- Colorful, readable terminal output
- 100% free and open source

---

## 📦 Installation

```bash
git clone https://github.com/Afaguayo/emailleakscanner.git
cd emailleakscanner
pip install -r requirements.txt
⚙️ Setup
Create a .env file inside the project folder.

Add your HaveIBeenPwned API key:

ini
Copy
Edit
HIBP_API_KEY=your_hibp_api_key_here
If you don't have an API key, you can still run the tool — it will simply skip the HIBP check.

Get your free HIBP key here: https://haveibeenpwned.com/API/Key

🛠️ Usage
bash
Copy
Edit
python emailleakscanner.py
Enter your email when prompted.

View breach results from LeakCheck, HaveIBeenPwned (if key provided), and Google search!

📜 Example Output
![example output screenshot here if you want]

⚠️ Legal Disclaimer
This tool is for personal use and educational purposes only.
Only check emails you own or have permission to scan.

🧠 Built With
Python 3

Requests

BeautifulSoup4

Python-Dotenv

Colorama

🛡️ License
This project is licensed under the MIT License.

❤️ Acknowledgments
LeakCheck.net

HaveIBeenPwned.com

The open-source security community