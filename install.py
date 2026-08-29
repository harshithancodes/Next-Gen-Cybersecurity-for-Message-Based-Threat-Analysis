#!/usr/bin/env python3
"""
Gmail Threat Detection System - Simple Installation Script
No external databases required - uses built-in SQLite
"""

import os
import sys
import subprocess
import platform

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║   🛡️  Gmail Threat Detection - Simple Installation          ║
    ║                                                              ║
    ║   ✅ No Redis required                                       ║
    ║   ✅ No MongoDB required                                     ║
    ║   ✅ Uses built-in SQLite                                    ║
    ║   ✅ Minimal dependencies                                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check Python version"""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        print(f"   Current version: {sys.version}")
        return False
    else:
        print(f"✅ Python {sys.version.split()[0]} - OK")
        return True

def install_dependencies():
    """Install required packages"""
    print("\n📦 Installing dependencies...")
    
    packages = [
        'numpy>=1.20.0',
        'pandas>=1.3.0',
        'scikit-learn>=1.0.0',
        'nltk>=3.7',
        'google-auth>=2.0.0',
        'google-auth-oauthlib>=1.0.0',
        'google-api-python-client>=2.0.0',
        'flask>=2.0.0',
        'requests>=2.25.0'
    ]
    
    for package in packages:
        print(f"   Installing {package}...")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', package, '--quiet'
            ])
            print(f"   ✅ {package}")
        except subprocess.CalledProcessError:
            print(f"   ❌ Failed to install {package}")
            return False
    
    return True

def setup_directories():
    """Create necessary directories"""
    print("\n📁 Setting up directories...")
    
    directories = ['data', 'models', 'logs', 'backups']
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"   ✅ {directory}/")
        except Exception as e:
            print(f"   ❌ Failed to create {directory}/: {e}")
            return False
    
    return True

def download_nltk_data():
    """Download required NLTK data"""
    print("\n📚 Downloading NLTK data...")
    
    try:
        import nltk
        
        nltk_data = ['punkt', 'stopwords', 'vader_lexicon']
        
        for data in nltk_data:
            print(f"   Downloading {data}...")
            nltk.download(data, quiet=True)
            print(f"   ✅ {data}")
            
        return True
        
    except Exception as e:
        print(f"   ❌ NLTK download failed: {e}")
        return False

def create_sample_config():
    """Create sample configuration file"""
    print("\n⚙️ Creating configuration files...")
    
    # Create sample .env file
    env_content = """# Gmail Threat Detection Configuration
# Simple setup - no external databases required

# Gmail API
GOOGLE_CREDENTIALS_PATH=./credentials.json
GOOGLE_PROJECT_ID=your-project-id

# Threat Detection
PHISHING_THRESHOLD=0.7
SPAM_THRESHOLD=0.6
MALWARE_THRESHOLD=0.8
OVERALL_RISK_THRESHOLD=0.6

# System Settings
CHECK_INTERVAL=30
MAX_EMAILS_PER_CHECK=50
API_PORT=5000
LOG_LEVEL=INFO

# Database (SQLite - built-in)
SQLITE_DATABASE=./data/threat_detection.db
DATA_DIRECTORY=./data
"""
    
    try:
        with open('.env.example', 'w') as f:
            f.write(env_content)
        print("   ✅ .env.example created")
    except Exception as e:
        print(f"   ❌ Failed to create .env.example: {e}")
        return False
    
    # Create README
    readme_content = """# Gmail Threat Detection System

## Quick Start

1. **Install dependencies:**
   ```bash
   python install.py
   ```

2. **Get Gmail API credentials:**
   - Go to https://console.cloud.google.com/
   - Create/select project
   - Enable Gmail API
   - Create OAuth2 credentials
   - Download as `credentials.json`

3. **Run the system:**
   ```bash
   python run.py
   ```

4. **Access the dashboard:**
   - Open `dashboard.html` in your browser
   - API available at http://localhost:5000

## Features

✅ Real-time email monitoring
✅ AI-powered threat detection
✅ Phishing & spam filtering
✅ Malware scanning
✅ URL analysis
✅ Automated responses
✅ Built-in SQLite database (no setup required)

## No External Dependencies

- ❌ No Redis required
- ❌ No MongoDB required  
- ✅ Uses built-in SQLite
- ✅ Minimal setup
"""
    
    try:
        with open('README.md', 'w') as f:
            f.write(readme_content)
        print("   ✅ README.md created")
    except Exception as e:
        print(f"   ❌ Failed to create README.md: {e}")
    
    return True

def test_installation():
    """Test the installation"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test imports
        imports_to_test = [
            'numpy', 'pandas', 'sklearn', 'nltk',
            'google.oauth2', 'googleapiclient', 'flask',
            'sqlite3', 'json', 'asyncio'
        ]
        
        for module in imports_to_test:
            try:
                __import__(module.replace('-', '_'))
                print(f"   ✅ {module}")
            except ImportError:
                print(f"   ❌ {module} - import failed")
                return False
        
        # Test SQLite
        import sqlite3
        test_db = sqlite3.connect(':memory:')
        test_db.execute('CREATE TABLE test (id INTEGER)')
        test_db.close()
        print("   ✅ SQLite database test")
        
        # Test basic ML functionality
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.feature_extraction.text import TfidfVectorizer
        
        # Quick ML test
        vectorizer = TfidfVectorizer()
        model = MultinomialNB()
        
        sample_data = ["test email", "another test"]
        sample_labels = [0, 1]
        
        X = vectorizer.fit_transform(sample_data)
        model.fit(X, sample_labels)
        
        print("   ✅ Machine learning components")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Installation test failed: {e}")
        return False

def show_next_steps():
    """Show what to do next"""
    print("\n🎯 Next Steps")
    print("=" * 50)
    
    print("1. 📧 Set up Gmail API credentials:")
    print("   • Go to https://console.cloud.google.com/")
    print("   • Create/select a project") 
    print("   • Enable Gmail API")
    print("   • Create OAuth2 credentials")
    print("   • Download and save as 'credentials.json'")
    
    print("\n2. 🚀 Run the system:")
    print("   python run.py")
    
    print("\n3. 🌐 Access the interface:")
    print("   • Dashboard: Open dashboard.html in browser")
    print("   • API: http://localhost:5000")
    
    print("\n4. 📊 Monitor threats:")
    print("   • Real-time email scanning")
    print("   • Automatic threat detection")
    print("   • Instant alerts and actions")

def main():
    """Main installation function"""
    print_banner()
    
    print("🔧 Starting installation...")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        print("\n❌ Installation failed - Python version requirement not met")
        return False
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Installation failed - dependency installation failed")
        return False
    
    # Setup directories
    if not setup_directories():
        print("\n❌ Installation failed - directory setup failed")
        return False
    
    # Download NLTK data
    if not download_nltk_data():
        print("\n⚠️ NLTK data download failed (will retry at runtime)")
    
    # Create config files
    if not create_sample_config():
        print("\n⚠️ Configuration file creation failed (not critical)")
    
    # Test installation
    if not test_installation():
        print("\n❌ Installation test failed")
        return False
    
    # Success!
    print("\n🎉 Installation completed successfully!")
    print("=" * 60)
    
    print("\n✅ What was installed:")
    print("   • Core ML libraries (numpy, pandas, scikit-learn)")
    print("   • NLP tools (NLTK)")
    print("   • Gmail API client")
    print("   • Web framework (Flask)")
    print("   • Built-in SQLite database")
    print("   • All required directories")
    
    print("\n🚀 System Capabilities:")
    print("   • Real-time Gmail monitoring")
    print("   • AI-powered threat detection")
    print("   • Phishing & spam filtering")
    print("   • Malware scanning")
    print("   • URL analysis")
    print("   • Automated responses")
    print("   • Web dashboard & API")
    
    show_next_steps()
    
    return True

if __name__ == "__main__":
    success = main()
    
    if success:
        print(f"\n🏁 Installation complete! System ready to deploy.")
        sys.exit(0)
    else:
        print(f"\n💥 Installation failed. Please check the errors above.")
        sys.exit(1)