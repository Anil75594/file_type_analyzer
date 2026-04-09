# File Type Analyzer (Cybersecurity Project)

This project compares a file’s **extension** with its **real type** detected from the file’s magic number (signature), and calculates **MD5** + **SHA256** hashes.

## Project Structure

```
/project
├── app.py
├── templates/
│     └── index.html
├── static/
│     ├── style.css
│     └── script.js
```

## Run Instructions

1. Install Flask:

```bash
pip install flask
```

2. Start the server:

```bash
python app.py
```

3. Open in your browser:

- `http://127.0.0.1:5000`

If port 5000 is already in use on your machine, the app will automatically start on:

- `http://127.0.0.1:5001`

## How It Works

- Upload a file in the UI
- Backend reads the first bytes (magic number)
- Detects the likely real file type (PNG/JPEG/PDF/ZIP/EXE/etc.)
- Compares extension vs detected type
- If mismatch → **Suspicious file detected**


Output:

<img width="802" height="705" alt="2-file-type-analyzer" src="https://github.com/user-attachments/assets/24697093-a3f3-4f3c-a7c8-b26d4fd6d55d" />
