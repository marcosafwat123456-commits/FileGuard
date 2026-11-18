# 🛡️ FileGuard - Suspicious File Analysis Platform

**FileGuard** is a simple, modern, and professional cloud-computing-ready web application built for suspicious file analysis and static heuristic triage.

It allows security analysts, administrators, and students to safely inspect untrusted files, extract cryptographic hashes (SHA-256, SHA-1, MD5), analyze Shannon entropy (randomness density for detecting encryption or packers), detect file type spoofing via magic byte headers, and evaluate clear heuristic threat indicators.

> **🛡️ Zero-Execution Policy:** Uploaded files are treated purely as inert byte streams and are **never executed**, loaded as libraries, or run on the host system.
>
> **⚠️ Educational Disclaimer:** FileGuard uses static heuristics for educational triage. It is **not** a replacement for full endpoint antivirus (EDR/AV) and does **not** claim to detect all zero-day or runtime-only malware. No fake scanning results or proprietary engine signatures are simulated.

---

## 🌟 Key Features

1. **Dashboard:**
   - Real-time threat telemetry KPI counters (Total Scans, Flagged Threats, Clean Files, Average Shannon Entropy).
   - High-tech cybersecurity theme with dark mode, glowing neon green accents, and interactive radar visual.
   - Cloud architecture overview detailing stateless triage in AWS, Azure, and Google Cloud pipelines.
   - Quick Heuristic Test Bed with 4 instant educational simulation presets.

2. **Interactive File Scanner:**
   - Cyber drag-and-drop dropzone with animated scanning sweep.
   - 16 MB upload limit and secure filename sanitization.
   - Multi-phase progress tracking (Upload -> Hashing -> Shannon Entropy -> Static Heuristics).
   - Instant verdict banner (Clean, Low Risk, Suspicious, High Risk) with Threat Score gauge (0–100).
   - Cryptographic hashes display with 1-click clipboard copy.

3. **Scan History:**
   - Persistent local SQLite database storage (`data/fileguard.db`). Zero external database configuration required.
   - Live search filter by filename, hash, or verdict.
   - Filter pills (All, High Risk, Suspicious, Clean).
   - Instant export to JSON or formatted text reports.
   - Individual record deletion and complete history purge options.

4. **Forensic Analysis Reports:**
   - Standalone and printable report views (`/report/<scan_id>`).
   - Threat score gauge and executive assessment summary.
   - Shannon Entropy meter with 16-segment distribution chart showing where byte randomness spikes occur.
   - Triggered heuristic rules with category, severity, matched evidence string, and educational explanations.
   - Initial 128-byte raw hex and ASCII stream inspection view.
   - Export report as JSON or formatted text file.

5. **About & Architecture:**
   - Detailed breakdown of static heuristics: Shannon Entropy, Magic Byte Header Inspection, Double Extensions, Living-off-the-Land (LotL) binaries, and RTLO character tricks.
   - Cloud deployment blueprint for containerization and storage bucket integration.

---

## 📁 Project Structure

```text
FileGuard/
├── app.py                   # Main Flask application, routes, and REST API
├── config.py                # App configuration (paths, 16MB limit, secrets)
├── database.py              # SQLite persistence layer and query helpers
├── requirements.txt         # Lightweight Python dependencies (Flask, Werkzeug)
├── run.bat                  # 1-Click Windows launch script
├── README.md                # Documentation and Windows setup guide
│
├── analyzer/                # Static Heuristic Analysis Engine
│   ├── __init__.py
│   ├── core.py              # FileAnalyzer coordinator (hashing, hex dump, scoring)
│   ├── entropy.py           # Shannon entropy calculation & 16-chunk analyzer
│   ├── magic_types.py       # Pure-Python magic byte signature inspection
│   └── heuristics.py        # Static string patterns, LotL detection, & spoofing checks
│
├── templates/               # Frontend HTML Templates
│   ├── base.html            # Cybersecurity layout, navigation, and live status
│   ├── index.html           # Main Single-Page Application container (5 tabs)
│   └── report.html          # Standalone printable analysis report template
│
├── static/                  # Frontend Static Assets
│   ├── css/
│   │   └── style.css        # Cybersecurity SOC dark theme design system
│   └── js/
│       └── main.js          # SPA navigation, upload handler, search, and charts
│
└── data/                    # Local storage (created automatically on first run)
    └── fileguard.db         # Embedded SQLite database
```

---

## 💻 Step-by-Step Windows Setup & Run Guide

### Step 1: Verify Python Installation
Open **Command Prompt** (`cmd.exe`) or **PowerShell** and verify that Python 3.8 or newer is installed:

```cmd
python --version
```

*(If Python is not recognized, download and install it from [python.org](https://www.python.org/). Make sure to check the box **"Add Python to PATH"** during installation).*

---

### Step 2: Open the Project Directory
Navigate to the FileGuard project folder in your terminal:

```cmd
cd "c:\Users\Marco Safwat\3D Objects\FileGuard-"
```

---

### Step 3 (Recommended): Create and Activate a Virtual Environment
Creating a virtual environment ensures clean, isolated dependencies:

```cmd
python -m venv venv
```

Activate the virtual environment on Windows:
- **Command Prompt (`cmd.exe`):**
  ```cmd
  venv\Scripts\activate.bat
  ```
- **PowerShell:**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```

---

### Step 4: Install Dependencies
Install the required packages using `pip`:

```cmd
python -m pip install -r requirements.txt
```

*(Note: FileGuard utilizes pure Python byte inspection, so it requires zero C++ build tools or external DLLs).*

---

### Step 5: Start the FileGuard Server
Run the Flask server:

```cmd
python app.py
```

You will see the startup banner:
```text
=================================================================
  FileGuard - Suspicious File Analysis Cloud Platform
  Version: 1.0.0 | Environment: Local Development
  Web Server: http://127.0.0.1:5000
=================================================================
  * Static byte-level heuristics active
  * Upload limit: 16 MB
  * Local SQLite storage: data/fileguard.db
  * NEVER executes uploaded files
=================================================================
```

---

### Step 6: Access the Web Application
Open your web browser (Chrome, Edge, Firefox, or Brave) and navigate to:

👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### ⚡ Quick 1-Click Launch on Windows (Alternative)
You can also launch FileGuard at any time simply by **double-clicking `run.bat`** in the project folder! The script will automatically verify dependencies and start the application.

---

## 🧪 Testing the Scanner with Sample Files

FileGuard includes built-in educational presets directly on the **Dashboard** and in the **File Scanner** tab. Click any preset to test the heuristics immediately:

1. **📄 Benign Text Report:** Clean text file, low entropy (~4.0), no suspicious strings. Verdict: **Clean (0/100)**.
2. **🚨 Disguised PDF (`invoice_urgent.pdf`):** A file named `.pdf` whose header starts with `MZ` (Windows PE executable). Triggers **Extension Spoofing**. Verdict: **High Risk (75/100)**.
3. **⚡ Obfuscated PowerShell (`sync_backup.ps1`):** Contains `-w hidden`, `-nop`, base64 `-enc`, and `vssadmin delete shadows`. Triggers **Ransomware / LotL indicators**. Verdict: **High Risk (80/100)**.
4. **⚠️ Double Extension VBS (`bonus.xlsx.vbs`):** Contains camouflaged double extension and living-off-the-land downloader (`certutil -urlcache`). Verdict: **Suspicious / High Risk**.

You can also drag and drop any file from your computer (up to 16 MB) to calculate its SHA-256 hash and inspect its byte characteristics.

---

## ☁️ Cloud Deployment Guide

FileGuard is designed to be cloud-native and stateless:

### Docker Deployment
Create a `Dockerfile` in the project root:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```
Build and run:
```bash
docker build -t fileguard .
docker run -p 5000:5000 fileguard
```

### Deploying to Render (Free Web Service)

FileGuard is pre-configured for **Render's Free Tier** using either automatic Blueprint detection (`render.yaml`) or manual setup.

#### Method 1: Automatic Blueprint (Easiest)
1. Push your FileGuard repository to **GitHub** or **GitLab**.
2. Sign in to your [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** and select **Blueprint**.
4. Connect your FileGuard repository.
5. Render will automatically detect [`render.yaml`](file:///c:/Users/Marco%20Safwat/3D%20Objects/FileGuard-/render.yaml) and pre-configure the Build Command (`pip install -r requirements.txt`) and Start Command (`gunicorn app:app`).
6. Click **Apply** to begin the deployment.

#### Method 2: Manual Web Service Setup
1. In the Render Dashboard, click **New +** > **Web Service**.
2. Select your repository.
3. Configure the following settings:
   - **Name:** `fileguard` (or any name you prefer)
   - **Language:** `Python 3`
   - **Region:** Any (e.g., Oregon, Frankfurt)
   - **Branch:** `main` (or `master`)
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** `Free`
4. Under **Advanced** > **Environment Variables**, add:
   - `PYTHON_VERSION`: `3.11.9`
   - `FLASK_ENV`: `production`
   - `SECRET_KEY`: *(Click "Generate" or provide a custom random key)*
5. Under **Health Check Path**, enter: `/healthz`
6. Click **Create Web Service**.

> **Note on Free Tier Inactivity:** Render puts free web services to sleep after 15 minutes of inactivity. When a new visitor accesses the URL, it will take about 30–50 seconds to wake up.

---

## 🔒 Security & Privacy Notes

- **No Remote Calls:** No files or hashes are transmitted to external servers or third-party APIs. All processing occurs locally on your machine.
- **Zero Execution:** Files are never launched or executed.
- **File Handling:** Read in chunks up to 16 MB. Temporary files are safely cleaned up.

---

## 📚 منظم مواد الكلية (GitHub Pages)

يتضمن المستودع موقعًا ثابتًا مستقلًا لإدارة مواد الكلية، إلى جانب تطبيق FileGuard الأصلي. الموقع موجود في مجلد `docs/` ويعمل مباشرةً من المتصفح دون Flask أو خادم أو استضافة خارجية. يتيح إضافة المواد وتعديلها وحذفها، وكتابة ملاحظات لكل مادة، ورفع الملفات وتنزيلها وحذفها.

### تفعيل النشر على GitHub Pages

1. ادفع التغييرات إلى فرع `main` في GitHub.
2. من المستودع، افتح **Settings → Pages** واختر **GitHub Actions** كمصدر للنشر.
3. سيعمل سير العمل `.github/workflows/pages.yml` تلقائيًا عند تحديث ملفات الموقع، ويمكن تشغيله يدويًا من تبويب **Actions**.
4. بعد نجاح سير العمل، افتح الرابط الظاهر في **Settings → Pages**. غالبًا يكون بالشكل `https://<اسم-المستخدم>.github.io/FileGuard/`.

### التخزين والخصوصية

المواد والملاحظات محفوظة في تخزين المتصفح المحلي، والملفات محفوظة في **IndexedDB** على الجهاز الذي تستخدمه. لا تُرسل البيانات إلى خادم ولا تتم مزامنتها بين الأجهزة أو المتصفحات. حذف بيانات الموقع/المتصفح قد يحذف المواد والملفات؛ استخدم الجهاز والمتصفح نفسيهما للاحتفاظ بها. يتطلب النشر استخدام HTTPS، وهو ما يوفره GitHub Pages.
