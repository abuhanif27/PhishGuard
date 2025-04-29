# PhishGuard - AI-Powered Phishing Detection

PhishGuard is an intelligent phishing detection system that helps identify and protect against phishing attempts in URLs and emails.

## 🚀 Quick Start

Setting up PhishGuard is simple:

1. Make sure you have **Python 3.8+** installed on your system
2. Clone or download this repository 
3. Open a terminal/command prompt and navigate to the project folder
4. Run the setup script:

```bash
python setup.py
```

That's it! The script will:
- Create a virtual environment
- Install all necessary dependencies
- Download required NLTK data
- Set up the database
- Test the system
- Start the development server

## 📱 Using PhishGuard

Once running, navigate to http://127.0.0.1:8000/ in your web browser.

PhishGuard offers:
- **URL Scanner**: Analyze URLs for phishing indicators
- **Email Analyzer**: Check emails for suspicious content
- **Dashboard**: View your scan history and manage your account

## 🛠️ Manual Setup (if needed)

If you prefer to set up manually:

1. Create a virtual environment:
   ```
   python -m venv venv
   
   # Windows:
   venv\Scripts\activate
   
   # Mac/Linux:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Download NLTK data:
   ```
   python -c "import nltk; nltk.download('punkt')"
   ```

4. Run migrations:
   ```
   python manage.py migrate
   ```

5. Start the server:
   ```
   python manage.py runserver
   ```

## ⚡ Optional ML Features

For machine learning-based detection:
1. Open `requirements.txt` in a text editor
2. Uncomment the ML dependencies (remove the # symbols)
3. Run `pip install -r requirements.txt` again

## 🔍 Troubleshooting

Common issues:

1. **"Package not found" errors**:
   - Make sure your virtual environment is activated
   - Try running `pip install [package-name]` for the specific package

2. **NLTK data issues**:
   - Run `python -c "import nltk; nltk.download()"`
   - In the downloader window, select "punkt" from the "Models" tab

3. **Import errors in Python Anywhere**:
   - Make sure to install all dependencies in your Python Anywhere environment
   - Double-check your WSGI configuration file

## 📖 License

This project is licensed under the MIT License. 