#!/usr/bin/env python3
"""
Database Schema Fix for Gmail Threat Detection
Adds missing tables and fixes database issues
"""

import sqlite3
import os
from datetime import datetime

def fix_database_schema():
    """Fix the database schema by adding missing tables"""
    
    db_path = 'data/enhanced_threat_detection.db'
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    print(f"🔧 Fixing database schema at: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Add missing processed_emails table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE NOT NULL,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                account_email TEXT,
                risk_score REAL DEFAULT 0.0
            )
        ''')
        print("✅ Added processed_emails table")
        
        # Ensure all other tables exist with correct schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE,
                timestamp TEXT,
                sender TEXT,
                subject TEXT,
                overall_risk REAL,
                phishing_score REAL,
                spam_score REAL,
                malware_score REAL,
                url_score REAL,
                confidence REAL,
                explanation TEXT,
                actions_taken TEXT,
                email_content TEXT,
                attachment_count INTEGER,
                url_count INTEGER,
                processing_time REAL,
                account_email TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✅ Verified enhanced_threats table")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                priority TEXT,
                email_id TEXT,
                sender TEXT,
                subject TEXT,
                risk_score REAL,
                threat_types TEXT,
                explanation TEXT,
                actions_taken TEXT,
                account_email TEXT,
                resolved BOOLEAN DEFAULT FALSE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✅ Verified enhanced_alerts table")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                total_analyzed INTEGER,
                high_risk INTEGER,
                medium_risk INTEGER,
                low_risk INTEGER,
                phishing_detected INTEGER,
                spam_detected INTEGER,
                malware_detected INTEGER,
                urls_analyzed INTEGER,
                actions_taken INTEGER,
                account_email TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✅ Verified system_statistics table")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS account_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_address TEXT,
                login_time TEXT,
                logout_time TEXT,
                session_active BOOLEAN DEFAULT TRUE,
                emails_processed INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✅ Verified account_sessions table")
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_processed_emails_id ON processed_emails(email_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_email_id ON enhanced_threats(email_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON enhanced_alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_risk ON enhanced_threats(overall_risk)')
        print("✅ Created performance indexes")
        
        conn.commit()
        conn.close()
        
        print("✅ Database schema fixed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Database fix failed: {e}")
        return False

def clear_processed_emails():
    """Clear processed emails to force re-processing"""
    try:
        db_path = 'data/enhanced_threat_detection.db'
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM processed_emails')
        cleared = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ Cleared {cleared} processed email records")
        print("   System will now re-process recent emails")
        return True
        
    except Exception as e:
        print(f"❌ Failed to clear processed emails: {e}")
        return False

def increase_email_limits():
    """Show how to increase email detection limits"""
    print("\n📊 To detect more emails, update these settings in your code:")
    print("1. In monitor_emails_enhanced() method:")
    print("   Change: messages = self.gmail_client.get_messages(query='is:unread', max_results=5)")
    print("   To:     messages = self.gmail_client.get_messages(query='is:unread', max_results=20)")
    
    print("\n2. In the processing loop:")
    print("   Change: if processed_count >= 3:")
    print("   To:     if processed_count >= 10:")
    
    print("\n3. To check all recent emails, not just unread:")
    print("   Change: query='is:unread'")
    print("   To:     query='newer_than:1d'  # Last 24 hours")

def lower_threat_thresholds():
    """Show how to lower threat detection thresholds"""
    print("\n🎯 To detect more threats, lower these thresholds:")
    print("1. In __init__ method:")
    print("   Change: self.threat_threshold = 0.6")
    print("   To:     self.threat_threshold = 0.3")
    
    print("\n2. In take_enhanced_action method:")
    print("   Change: if analysis.overall_risk > 0.4:")
    print("   To:     if analysis.overall_risk > 0.2:")

def test_threat_detection():
    """Test threat detection with a sample"""
    print("\n🧪 Test your threat detection by accessing:")
    print("   http://127.0.0.1:8888/analyze")
    print("\nOr use the 'Test Analysis' button in the dashboard")
    
    sample_threats = [
        "URGENT: Your account will be suspended! Click here: http://fake-bank.com/verify",
        "Congratulations! You've won $1,000,000! Claim now: http://scam-lottery.net",
        "Your PayPal account has been limited. Verify immediately: http://fake-paypal.com",
        "Security alert: Suspicious login detected. Confirm your identity now!",
        "Free money! Make $5000/day working from home! No experience needed!"
    ]
    
    print("\nSample threat emails to test:")
    for i, threat in enumerate(sample_threats, 1):
        print(f"{i}. {threat[:80]}...")

def main():
    """Main function"""
    print("🛠️ Gmail Threat Detection - Database & Configuration Fix")
    print("=" * 60)
    
    # Fix database schema
    if fix_database_schema():
        print("\n🔄 Database fixed! Now you can:")
        print("1. Clear processed emails to re-scan recent messages")
        print("2. Update email limits for more detection")
        print("3. Lower threat thresholds for more sensitive detection")
        print("4. Test threat detection manually")
        
        print("\nWhat would you like to do?")
        print("1. Clear processed emails (recommended)")
        print("2. Show email limit settings")
        print("3. Show threat threshold settings") 
        print("4. Show testing instructions")
        print("5. Do all of the above")
        print("6. Exit")
        
        try:
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                clear_processed_emails()
                
            elif choice == '2':
                increase_email_limits()
                
            elif choice == '3':
                lower_threat_thresholds()
                
            elif choice == '4':
                test_threat_detection()
                
            elif choice == '5':
                clear_processed_emails()
                increase_email_limits()
                lower_threat_thresholds()
                test_threat_detection()
                
            elif choice == '6':
                print("👋 Done!")
                
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Interrupted")

if __name__ == "__main__":
    main()