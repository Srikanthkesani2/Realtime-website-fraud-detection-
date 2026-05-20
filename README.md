
# 🛡️ Real-Time Website Threat Detection & AI Cyber Security Assistant

An AI-powered cyber security web application that detects whether a website URL is potentially **phishing or malicious** using a trained Machine Learning model. The system also generates an **AI-based security analysis report** using Google Gemini and allows users to optionally raise a **cyber-crime complaint via email**.

Built using **Flask + Machine Learning + Gemini AI** for real-time URL threat analysis. 🚀

---

# 🚀 Features

## ✅ Phishing Website Detection
- Detects whether a URL is:
  - Legitimate
  - Suspicious / Phishing
- Uses a trained ML classification model with PCA transformation.

## 🤖 AI Security Report Generation
- Generates human-readable cyber security insights using **Google Gemini API**
- Explains:
  - Risk level
  - Possible dangers
  - Safety recommendations
  - Final verdict

## 💬 AI Follow-up Questions
Users can ask questions like:
- “Is it safe to login?”
- “Can this website steal passwords?”
- “Why is this URL suspicious?”

## 📧 Cyber Crime Complaint System
- Users can raise complaints directly from the UI
- Supports:
  - Screenshot uploads
  - Contact details
  - Complaint notes
- Complaint gets emailed using SMTP integration

## ⚡ Real-Time Analysis
- Instant feature extraction
- Fast prediction pipeline
- Lightweight Flask web interface

---

# 🧠 Tech Stack

## 🔹 Backend
- Python
- Flask
- PyCaret
- Scikit-learn
- PCA
- Google Gemini API
- Flask-Mail
- HTTPX
- Whois

## 🔹 Frontend
- HTML
- Bootstrap 5
- Jinja2 Templates

---

# 📌 How the System Works

## 1️⃣ URL Submission
User enters a URL through the web interface.

Example:
```bash
https://example.com
```

---

## 2️⃣ Feature Extraction
The system extracts multiple phishing-related features such as:

### 🔍 URL Based Features
- URL Length
- URL Depth
- TinyURL Detection
- Number of Dots
- Hyphen Usage
- Sensitive Keywords

### 🌐 Domain Features
- Domain Age
- Domain Expiry
- WHOIS Information

### ⚠️ HTML / JavaScript Heuristics
- iframe detection
- Suspicious mouse-over scripts
- Redirect/forwarding detection

---

## 3️⃣ PCA Transformation
Extracted features are transformed using a trained PCA model to improve ML performance.

---

## 4️⃣ Machine Learning Prediction
The trained ML model predicts:
- Phishing
- Legitimate

Also returns:
- Confidence score
- Prediction probability

---

## 5️⃣ AI Security Report
Google Gemini generates a readable security report containing:
- Risk level
- Why the site is suspicious
- Possible risks
- Safety tips
- Final recommendation

---

## 6️⃣ Complaint Generation
Users can:
- Upload screenshots
- Add complaint notes
- Submit cyber-crime complaints via email

---

# 📂 Project Structure

```bash
├── app.py
├── featureExtractor.py
├── extractorFunctions.py
├── gemini_report.py
├── requirements.txt
│
├── model/
│   ├── phishingdetection
│   └── pca_model.pkl
│
├── templates/
│   └── index.html
│
├── static/
│   └── uploads/
│
└── README.md
```

---

# ⚙️ Installation & Setup

## 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/phishing-detection-ai.git
cd phishing-detection-ai
```

---

## 2️⃣ Create Virtual Environment

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Mac
```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 Environment Variables

Create a `.env` file in the root directory.

## Gemini API
```env
GEMINI_API_KEY=your_gemini_api_key
```

## Email Configuration
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
```

> Gmail users should use an App Password instead of their actual password.

---

# ▶️ Run the Project

```bash
python app.py
```

Open in browser:
```bash
http://127.0.0.1:5000
```

---

# 💡 Usage

## Analyze a Website
1. Enter URL
2. Click **Analyze Website**
3. View:
   - Prediction
   - Confidence Score
   - AI Security Report

---

## Ask AI Questions
Examples:
```bash
Is this website safe?
Can this site steal passwords?
Why is this URL suspicious?
```

---

## Raise Complaint
- Fill complaint form
- Upload screenshot (optional)
- Submit report

---

# 📊 Machine Learning Pipeline

```bash
URL → Feature Extraction → PCA → ML Model → Prediction → Gemini AI Report
```

---

# 🛠️ Key Modules

| File | Description |
|---|---|
| `app.py` | Main Flask application |
| `featureExtractor.py` | Extracts phishing-related features |
| `extractorFunctions.py` | Helper feature functions |
| `gemini_report.py` | Gemini AI integration |
| `templates/index.html` | Frontend UI |
| `model/` | Trained ML model + PCA model |

---

# ⚠️ Limitations

- WHOIS lookup may fail for some domains
- Gemini API has rate limits
- ML prediction accuracy depends on training data
- This is a research/demo project and not a production-grade security system

---

# 🧪 Future Improvements

- Browser extension support
- Real-time blacklist integration
- Deep learning models
- Admin dashboard
- Threat history tracking
- Multi-language support
- Cloud deployment

---

# 📸 Screenshots

Add screenshots here:

```bash
screenshots/home.png
screenshots/result.png
screenshots/report.png
```

---

# 🤝 Contributing

Contributions are welcome.

```bash
Fork → Clone → Create Branch → Commit → Push → Pull Request
```

---

# 📜 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

Developed by **Sriks** 🚀

---

# ⭐ Support

If you like this project:
- Star the repository ⭐
- Fork it 🍴
- Share it 🚀
