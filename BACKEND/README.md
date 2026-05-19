# Amaan Flask Backend

This is the demo API for the Amaan travel insurance MVP.

## Install Python

Python is not currently available from the terminal. Install it from:

https://www.python.org/downloads/windows/

During install, tick **Add python.exe to PATH**.

## Run Locally

```powershell
cd "C:\Users\Sufyan Saleh\Documents\New project\backend"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Open:

```text
http://127.0.0.1:5000/health
```

Demo accounts:

```text
admin@gmail.com / 1234
user1@gmail.com / 1234
MFA demo code: 123456
```

## Supabase

The MVP runs from CSV files by default. To connect Supabase, put your project URL and service key in `.env`.
The API is structured so Supabase can replace the in-memory demo store after the presentation database schema is confirmed.
