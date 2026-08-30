#!/usr/bin/env python3
"""
Enhanced Gmail Real-time Cybersecurity Threat Detection System
Fixed version with proper threat detection logic
"""

import os
import sys
import asyncio
import base64
import json
import re
import hashlib
import requests
import pickle
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urlparse
from collections import defaultdict, Counter

# Fix Windows encoding issues
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

# Core dependencies
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.cluster import DBSCAN
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Gmail API
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Web framework
from flask import Flask, jsonify, request, render_template_string

# NLP
import nltk
try:
    from textblob import TextBlob
except ImportError:
    TextBlob = None

try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('vader_lexicon', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
except:
    pass

# Enhanced logging setup
import logging

class AdvancedThreatLogger(logging.StreamHandler):
    """Enhanced logger with comprehensive threat detection formatting"""
    
    def emit(self, record):
        try:
            msg = self.format(record)
            
            # Enhanced color coding for all threat types
            if 'APT DETECTED' in msg or 'ADVANCED PERSISTENT' in msg:
                msg = f"\033[95m{msg}\033[0m"  # Magenta for APT
            elif 'DDOS' in msg or 'DOS ATTACK' in msg:
                msg = f"\033[91m{msg}\033[0m"  # Red for DDoS
            elif 'INSIDER THREAT' in msg:
                msg = f"\033[93m{msg}\033[0m"  # Yellow for insider threats
            elif 'CRITICAL THREAT' in msg:
                msg = f"\033[91m{msg}\033[0m"  # Red
            elif 'HIGH THREAT' in msg:
                msg = f"\033[93m{msg}\033[0m"  # Yellow
            elif 'MEDIUM THREAT' in msg:
                msg = f"\033[94m{msg}\033[0m"  # Blue
            elif 'LOW THREAT' in msg:
                msg = f"\033[96m{msg}\033[0m"  # Cyan
            elif 'SAFE' in msg:
                msg = f"\033[92m{msg}\033[0m"  # Green
                
            safe_msg = msg.encode('utf-8', errors='replace').decode('utf-8')
            if hasattr(self.stream, 'buffer'):
                self.stream.buffer.write(safe_msg.encode('utf-8', errors='replace'))
                self.stream.buffer.write(b'\n')
            else:
                self.stream.write(safe_msg)
                self.stream.write('\n')
            self.stream.flush()
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[AdvancedThreatLogger(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass
class ComprehensiveThreatAnalysis:
    """Enhanced threat analysis results"""
    email_id: str
    threat_types: Dict[str, float]
    overall_risk: float
    confidence: float
    explanation: str
    timestamp: datetime
    actions_taken: List[str]
    sender: str = ""
    subject: str = ""
    email_content: str = ""
    threat_indicators: List[str] = None
    # Enhanced threat classifications
    apt_indicators: List[str] = None
    ddos_indicators: List[str] = None
    insider_threat_score: float = 0.0
    behavioral_anomalies: List[str] = None
    network_indicators: Dict[str, str] = None
    email_metadata: Dict = None

@dataclass
class EmailData:
    """Enhanced email data structure"""
    id: str
    sender: str
    subject: str
    body: str
    headers: Dict
    attachments: List[Dict]
    urls: List[str]
    timestamp: datetime
    raw_message: Dict = None
    # Enhanced metadata
    sender_ip: str = ""
    routing_info: List[str] = None
    authentication_results: Dict = None
    message_size: int = 0
    encryption_status: str = ""

class AdvancedThreatDetectionModels:
    """Enhanced threat detection with comprehensive AI models - FIXED VERSION"""
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.behavioral_profiles = {}
        self.communication_patterns = defaultdict(list)
        self.sender_history = defaultdict(dict)
        
        # Load threat databases
        self.load_threat_databases()
        
        # Enhanced legitimate domain whitelist
        self.legitimate_domains = {
            'github.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'stripe.com', 'linkedin.com', 'facebook.com', 'twitter.com',
            'instagram.com', 'youtube.com', 'netflix.com', 'spotify.com', 'adobe.com',
            'salesforce.com', 'atlassian.com', 'slack.com', 'zoom.us', 'dropbox.com',
            'spline.design', 'railway.app', 'vercel.com', 'netlify.com', 'heroku.com',
            'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com', 'googleapis.com',
            'mail.spline.design', 'news.railway.app', 'notify.railway.app', 'gmail.com', 
            'outlook.com', 'yahoo.com', 'protonmail.com', 'icloud.com', 'oracle.com',
            'servicenow.com'
        }
        
        logger.info("THREAT DETECTION: Initializing advanced threat detection models...")
        self.load_or_train_models()
        
    def load_threat_databases(self):
        """Load comprehensive threat intelligence databases - ENHANCED"""
        
        # CRITICAL: Enhanced phishing patterns
        self.phishing_patterns = {
            'urgency_keywords': [
                'urgent', 'immediate', 'verify now', 'act now', 'expires today',
                'limited time', 'suspended', 'locked', 'restricted', 'verify immediately',
                'confirm now', 'update now', 'within 24 hours', 'expire', 'deadline'
            ],
            'credential_harvest': [
                'verify account', 'confirm identity', 'update password', 'login here',
                'click to verify', 'secure account', 'validate account', 'confirm details',
                'update information', 'verify identity'
            ],
            'financial_lures': [
                'refund', 'payment', 'invoice', 'billing', 'transaction', 'wire transfer',
                'bank account', 'credit card', 'paypal', 'payment method', 'financial'
            ],
            'authority_spoofing': [
                'security team', 'it department', 'system administrator', 'support team',
                'account team', 'fraud department', 'compliance', 'legal department'
            ],
            'suspicious_domains': [
                'paypal-security', 'amazon-verify', 'microsoft-security', 'google-security',
                'apple-id-security', 'bank-verify', 'secure-', 'verify-', 'update-',
                'login-', 'account-', 'security-'
            ]
        }
        
        # APT indicators
        self.apt_indicators = {
            'c2_domains': {
                'apt1-command.com', 'apt28-control.net', 'lazarus-c2.org',
                'cobalt-strike.net', 'empire-c2.com', 'beacon-control.net'
            },
            'apt_groups': {
                'apt1', 'apt28', 'apt29', 'lazarus', 'carbanak', 'dragonfly',
                'equation', 'shamoon', 'stuxnet', 'duqu', 'flame'
            },
            'spear_phishing_patterns': [
                'quarterly report', 'financial statement', 'meeting minutes',
                'project update', 'confidential document', 'board meeting',
                'strategic plan', 'budget proposal', 'merger details', 'due diligence',
                'financial report', 'please review', 'confidential', 'strategic planning'
            ],
            'sensitive_content': [
                'confidential', 'classified', 'restricted access', 'internal only',
                'board approved', 'executive level', 'sensitive', 'proprietary'
            ]
        }
        
        # DDoS attack patterns - ENHANCED
        self.ddos_patterns = {
            'volumetric_indicators': [
                'massive traffic surge', 'bandwidth exhaustion', 'packet flood',
                'udp flood', 'icmp flood', 'syn flood', 'amplification attack',
                'traffic spike', 'ddos', 'dos attack', 'network overload'
            ],
            'application_layer': [
                'http flood', 'slowloris', 'slow post', 'rudy attack',
                'get flood', 'post flood', 'ssl renegotiation'
            ],
            'botnet_signatures': [
                'mirai', 'conficker', 'zeus', 'necurs', 'gameover',
                'dridex', 'emotet', 'trickbot', 'botnet'
            ],
            'network_symptoms': [
                'server overload', 'connection timeout', 'service unavailable',
                '503 error', 'network congestion', 'response time', 'connectivity issues'
            ]
        }
        
        # Insider threat indicators - ENHANCED
        self.insider_threat_patterns = {
            'data_exfiltration': [
                'backup', 'copy files', 'download', 'export', 'database dump',
                'customer list', 'financial data', 'confidential', 'proprietary',
                'restricted', 'classified', 'access records', 'file transfer'
            ],
            'policy_violations': [
                'password sharing', 'unauthorized access', 'bypass security',
                'share credentials', 'admin privileges', 'system backdoor',
                'circumvent', 'workaround'
            ],
            'behavioral_red_flags': [
                'job opportunity', 'resume', 'interview', 'new position',
                'career change', 'leaving company', 'competitor offer',
                'new opportunities', 'portfolio', 'career move'
            ],
            'suspicious_requests': [
                'keep this between us', 'confidential request', 'off the record',
                'don\'t tell', 'personal use', 'for my portfolio'
            ]
        }
        
        # Enhanced malware signatures
        self.malware_signatures = {
            'ransomware_indicators': [
                '.locked', '.encrypted', '.crypto', '.vault', '.cerber',
                'ransom note', 'bitcoin payment', 'decryption key', 'files encrypted',
                'ransomware', 'pay bitcoin', 'encrypted files'
            ],
            'trojan_patterns': [
                'remote access', 'keylogger', 'screen capture',
                'credential theft', 'banking trojan', 'backdoor access'
            ],
            'social_engineering': [
                'download now', 'install immediately', 'security update required',
                'virus detected', 'malware found', 'system infected',
                'click to clean', 'remove virus now', 'security scan',
                'infected with', 'cleaner', 'antivirus'
            ],
            'malicious_extensions': [
                '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', 
                '.jar', '.cmd', '.msi', '.dll'
            ]
        }
        
        # Business Email Compromise patterns - ENHANCED
        self.bec_patterns = {
            'ceo_fraud': [
                'ceo request', 'urgent transfer', 'confidential transaction',
                'wire transfer', 'payment change', 'vendor payment',
                'executive request', 'board approved', 'immediate transfer'
            ],
            'invoice_fraud': [
                'invoice attached', 'payment request', 'bank details changed',
                'new account details', 'payment redirection', 'updated banking'
            ]
        }

    def load_or_train_models(self):
        """Load or train comprehensive AI models - FIXED"""
        try:
            # Try to load existing models
            self.models['phishing'] = joblib.load('models/enhanced_phishing_model.pkl')
            self.models['malware'] = joblib.load('models/enhanced_malware_model.pkl')
            self.models['apt'] = joblib.load('models/apt_detection_model.pkl')
            self.models['insider_threat'] = joblib.load('models/insider_threat_model.pkl')
            self.models['ddos'] = joblib.load('models/ddos_detection_model.pkl')
            self.vectorizers['email'] = joblib.load('models/enhanced_vectorizer.pkl')
            logger.info("THREAT DETECTION: Loaded pre-trained enhanced models successfully")
        except:
            logger.warning("THREAT DETECTION: Training new comprehensive AI models...")
            self.train_advanced_models()
            
    def train_advanced_models(self):
        """Train comprehensive AI models for all threat types - IMPROVED"""
        
        # Enhanced training data with more realistic examples
        training_data = self.generate_comprehensive_training_data()
        
        # Advanced TF-IDF vectorizer
        self.vectorizers['email'] = TfidfVectorizer(
            max_features=10000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95,
            lowercase=True,
            analyzer='word',
            sublinear_tf=True
        )
        
        X_email = self.vectorizers['email'].fit_transform(training_data['emails'])
        
        # Train enhanced phishing model
        self.models['phishing'] = LogisticRegression(
            C=1.0, random_state=42, max_iter=2000, class_weight='balanced'
        )
        self.models['phishing'].fit(X_email, training_data['phishing_labels'])
        
        # Train APT detection model
        self.models['apt'] = LogisticRegression(
            C=0.8, random_state=42, max_iter=2000, class_weight='balanced'
        )
        self.models['apt'].fit(X_email, training_data['apt_labels'])
        
        # Train insider threat model
        self.models['insider_threat'] = LogisticRegression(
            C=0.5, random_state=42, max_iter=2000, class_weight='balanced'
        )
        self.models['insider_threat'].fit(X_email, training_data['insider_labels'])
        
        # Train DDoS detection model
        self.models['ddos'] = LogisticRegression(
            C=0.6, random_state=42, max_iter=2000, class_weight='balanced'
        )
        self.models['ddos'].fit(X_email, training_data['ddos_labels'])
        
        # Enhanced malware detection
        self.models['malware'] = LogisticRegression(
            C=0.7, random_state=42, max_iter=2000, class_weight='balanced'
        )
        self.models['malware'].fit(X_email, training_data['malware_labels'])
        
        # Save all models
        os.makedirs('models', exist_ok=True)
        for model_name, model in self.models.items():
            joblib.dump(model, f'models/enhanced_{model_name}_model.pkl')
        
        for vec_name, vectorizer in self.vectorizers.items():
            joblib.dump(vectorizer, f'models/enhanced_{vec_name}_vectorizer.pkl')
        
        logger.info("THREAT DETECTION: Advanced AI models trained and saved successfully")

    def generate_comprehensive_training_data(self):
        """Generate comprehensive training data - MUCH MORE REALISTIC"""
        
        # Realistic phishing examples based on actual threats
        phishing_examples = [
            "URGENT: Your PayPal account has been suspended due to suspicious activity. Verify immediately at paypal-security-verify.net",
            "Amazon Security Alert: Unauthorized login detected. Confirm your identity at amazon-verify-security.com within 24 hours",
            "Microsoft: Your account will expire today. Update your password at microsoft-security-update.org immediately",
            "CEO Request: Please wire $50,000 to new vendor account urgently. Bank details: Account 123456789 Routing 987654321",
            "IT Security: All employees must update passwords at company-security-portal.net by end of day or account will be locked",
            "Bank Alert: Fraudulent charges detected on your card. Verify account details at secure-bank-verification.net immediately",
            "IRS Notice: Tax refund of $2,847 is ready for claim. Access at irs-refund-claim.gov before it expires",
            "Apple ID Security: Unusual activity detected from unknown device. Secure your account at apple-id-security.net now",
            "Google Security: Account breach detected from foreign IP. Change password at google-security-center.com immediately",
            "Your account has been limited. Click here to verify: paypal-security.net/verify-account",
            "Wire transfer requested by CEO - urgent payment of $75,000 needed today",
            "Invoice payment overdue - click to update billing information immediately",
            "Security alert: Login from new device requires verification within 2 hours",
            "Account suspended due to policy violation - verify identity to restore access"
        ]
        
        # APT-style spear phishing (realistic examples)
        apt_examples = [
            "Please review the attached quarterly financial report and provide feedback by tomorrow morning",
            "Strategic planning document attached - confidential board meeting materials for executive review",
            "Merger and acquisition details - please review the due diligence package confidentially",
            "Q4 financial report requires your review - contains sensitive revenue data",
            "Confidential: Board meeting minutes attached - please review before Friday's session",
            "Annual budget proposal attached - executive approval needed by EOD",
            "Strategic partnership agreement - confidential legal documents for review",
            "Financial audit findings - please review before external presentation to stakeholders",
            "Competitive intelligence report - market analysis and strategic recommendations attached",
            "Legal compliance documents - regulatory filing requirements for immediate review",
            "Executive compensation review - board-approved salary structures confidential document",
            "Customer database analysis - please review the quarterly metrics report",
            "Confidential project update - strategic initiative requires your input"
        ]
        
        # Realistic insider threat examples
        insider_examples = [
            "Looking for new career opportunities outside the company, need to backup some client files for my portfolio",
            "Can you help me access the customer database? Working on a special project from home this weekend",
            "Need to download financial data for analysis, working on presentation from personal laptop",
            "Company policies are getting restrictive, exploring opportunities at competitors",
            "Backing up important client files to personal cloud storage before going on vacation",
            "Can you share your login credentials? Need to access system while you're out",
            "Copying sensitive documents for external presentation to potential business partners",
            "Meeting with former colleagues next week to discuss industry opportunities",
            "Exploring cloud backup options for company data - what do you recommend?",
            "Interviewing with competitors this week - anyone know about their compensation packages?",
            "Need to export customer list for analysis - can you help with database access?",
            "Working from home permanently now, need to transfer files to personal systems",
            "Keep this between us - backing up proprietary code for my personal projects"
        ]
        
        # Realistic DDoS-related communications
        ddos_examples = [
            "ALERT: Massive traffic surge detected across all edge points - potential DDoS attack in progress",
            "Network performance degraded - users reporting timeouts and connection failures",
            "Unusual traffic patterns detected - investigating potential distributed denial of service attack",
            "Bandwidth utilization at maximum capacity - DDoS mitigation protocols activated",
            "Multiple botnet signatures identified - Mirai and Zeus patterns in network traffic",
            "Server response times severely degraded since 3AM - DDoS attack confirmed",
            "Firewall blocking increased malicious requests - coordinated attack from multiple IPs",
            "CDN reporting abnormal traffic spikes from various geographic regions worldwide",
            "Load balancer struggling with current request volume - DDoS protection engaged",
            "Emergency: Website completely inaccessible - coordinated DDoS attack underway",
            "Traffic flood detected from botnet sources - immediate mitigation required",
            "Network congestion due to coordinated attack - SYN flood patterns identified",
            "Multiple connection attempts from suspicious IP ranges - DDoS response activated"
        ]
        
        # Realistic malware-related content
        malware_examples = [
            "Your computer has been infected with ransomware - download security cleaner from virus-scanner.net immediately",
            "ALERT: Malware detected on your system - run emergency scan from security-cleanup.com",
            "Files have been encrypted by ransomware - pay Bitcoin for decryption key at unlock-files.net",
            "Trojan detected - unauthorized remote access established - secure system immediately",
            "Keylogger installed on your computer - change all passwords and run comprehensive scan",
            "Banking credentials compromised by malware - update account security settings now",
            "Your computer is part of a botnet - disconnect and clean system immediately",
            "Rootkit found - critical system files modified - reinstall operating system required",
            "Spyware detected - personal information being transmitted to external servers",
            "Critical security update required - download patch from windows-updates.exe immediately",
            "Virus quarantined - multiple infected files found in downloads folder",
            "System infected with advanced malware - download cleaner tool to remove threats",
            "Ransomware attack - files encrypted - payment required for decryption key"
        ]
        
        # Legitimate business emails (for comparison)
        legitimate_examples = [
            "Team meeting scheduled for Thursday 2 PM in conference room A",
            "Quarterly report attached for your review and approval - no urgent action needed",
            "Welcome to our newsletter! Latest product updates and features inside",
            "Your order #12345 has been shipped successfully, tracking number provided",
            "New employee onboarding session scheduled for Monday morning in building B",
            "Scheduled system maintenance window planned for Sunday 2-4 AM",
            "Customer support ticket #789 has been resolved, please review the solution",
            "Monthly team sync meeting: Please submit project status by Friday",
            "Birthday celebration for John tomorrow in break room at 3 PM",
            "Office supplies order form is due by end of week - submit requests",
            "Holiday party planning committee meeting scheduled for next Tuesday",
            "Performance review process begins next month - HR will send instructions",
            "New parking policy effective next month - please review attached guidelines"
        ]
        
        # Combine all training data
        all_emails = (phishing_examples + apt_examples + insider_examples + 
                     ddos_examples + malware_examples + legitimate_examples)
        
        # Create labels for each threat type
        total_emails = len(all_emails)
        
        # Phishing labels
        phishing_labels = ([1] * len(phishing_examples) + 
                          [0] * (total_emails - len(phishing_examples)))
        
        # APT labels  
        apt_labels = ([0] * len(phishing_examples) + 
                     [1] * len(apt_examples) + 
                     [0] * (total_emails - len(phishing_examples) - len(apt_examples)))
        
        # Insider threat labels
        insider_labels = ([0] * (len(phishing_examples) + len(apt_examples)) + 
                         [1] * len(insider_examples) + 
                         [0] * (total_emails - len(phishing_examples) - len(apt_examples) - len(insider_examples)))
        
        # DDoS labels
        ddos_labels = ([0] * (len(phishing_examples) + len(apt_examples) + len(insider_examples)) + 
                      [1] * len(ddos_examples) + 
                      [0] * (total_emails - len(phishing_examples) - len(apt_examples) - len(insider_examples) - len(ddos_examples)))
        
        # Malware labels
        malware_labels = ([0] * (len(phishing_examples) + len(apt_examples) + len(insider_examples) + len(ddos_examples)) + 
                         [1] * len(malware_examples) + 
                         [0] * len(legitimate_examples))
        
        return {
            'emails': all_emails,
            'phishing_labels': phishing_labels,
            'apt_labels': apt_labels,
            'insider_labels': insider_labels,
            'ddos_labels': ddos_labels,
            'malware_labels': malware_labels
        }

    def detect_enhanced_phishing(self, email_data: EmailData) -> Tuple[float, str, List[str]]:
        """Enhanced phishing detection - FIXED AND IMPROVED"""
        try:
            full_content = f"{email_data.subject} {email_data.body} {email_data.sender}".lower()
            phishing_indicators = []
            
            # Check sender domain legitimacy
            sender_domain = self.extract_domain(email_data.sender)
            is_legitimate_domain = any(domain in sender_domain for domain in self.legitimate_domains)
            
            # Rule-based scoring (improved)
            rule_score = 0.0
            
            # Check for urgency keywords
            urgency_count = 0
            for keyword in self.phishing_patterns['urgency_keywords']:
                if keyword in full_content:
                    urgency_count += 1
                    phishing_indicators.append(f"Urgency: {keyword}")
            
            if urgency_count >= 3:
                rule_score += 0.7
            elif urgency_count >= 2:
                rule_score += 0.5
            elif urgency_count >= 1:
                rule_score += 0.3
            
            # Credential harvesting detection
            for pattern in self.phishing_patterns['credential_harvest']:
                if pattern in full_content:
                    rule_score += 0.6
                    phishing_indicators.append(f"Credential harvesting: {pattern}")
            
            # Financial lures
            for pattern in self.phishing_patterns['financial_lures']:
                if pattern in full_content:
                    rule_score += 0.4
                    phishing_indicators.append(f"Financial lure: {pattern}")
            
            # Authority spoofing
            for pattern in self.phishing_patterns['authority_spoofing']:
                if pattern in full_content:
                    rule_score += 0.5
                    phishing_indicators.append(f"Authority spoofing: {pattern}")
            
            # BEC patterns
            for pattern in self.bec_patterns['ceo_fraud']:
                if pattern in full_content:
                    rule_score += 0.8
                    phishing_indicators.append(f"BEC/CEO Fraud: {pattern}")
            
            # Suspicious domain patterns
            for pattern in self.phishing_patterns['suspicious_domains']:
                if pattern in sender_domain or any(pattern in url for url in email_data.urls):
                    rule_score += 0.7
                    phishing_indicators.append(f"Suspicious domain: {pattern}")
            
            # Check for PayPal specific phishing
            if 'paypal' in full_content and 'verify' in full_content:
                if 'paypal.com' not in sender_domain:
                    rule_score += 0.9
                    phishing_indicators.append("PayPal phishing detected")
            
            # Check for Amazon phishing
            if 'amazon' in full_content and ('verify' in full_content or 'security' in full_content):
                if 'amazon.com' not in sender_domain:
                    rule_score += 0.9
                    phishing_indicators.append("Amazon phishing detected")
            
            # URL analysis
            for url in email_data.urls:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                
                # Check for suspicious domain patterns
                if any(sus in domain for sus in ['verify', 'secure', 'login', 'update', 'confirm']):
                    rule_score += 0.5
                    phishing_indicators.append(f"Suspicious URL domain: {domain}")
                
                # Domain spoofing detection
                for legit_domain in ['paypal.com', 'amazon.com', 'microsoft.com', 'google.com']:
                    if legit_domain.replace('.', '') in domain and legit_domain not in domain:
                        rule_score += 0.9
                        phishing_indicators.append(f"Domain spoofing: {domain}")
            
            # ML model prediction
            try:
                features = self.vectorizers['email'].transform([full_content])
                ml_proba = self.models['phishing'].predict_proba(features)[0]
                ml_score = ml_proba[1] if len(ml_proba) > 1 else 0.0
            except:
                ml_score = 0.0
            
            # Reduce false positives for legitimate domains
            if is_legitimate_domain and rule_score < 0.7:
                rule_score = max(0, rule_score - 0.3)
            
            # Combine scores with better weighting
            final_score = min((ml_score * 0.4) + (rule_score * 0.6), 1.0)
            
            # Generate explanation
            if final_score >= 0.85:
                risk_level = "CRITICAL PHISHING THREAT"
            elif final_score >= 0.7:
                risk_level = "HIGH PHISHING RISK"
            elif final_score >= 0.5:
                risk_level = "MEDIUM PHISHING RISK"
            else:
                risk_level = "LOW PHISHING RISK"
            
            explanation = f"{risk_level} - Domain: {sender_domain} - ML: {ml_score:.2f}, Rules: {rule_score:.2f}"
            
            return final_score, explanation, phishing_indicators
            
        except Exception as e:
            logger.error(f"Enhanced phishing detection error: {e}")
            return 0.0, f"Phishing detection error: {str(e)}", []

    def detect_advanced_persistent_threats(self, email_data: EmailData) -> Tuple[float, str, List[str]]:
        """Detect Advanced Persistent Threats (APTs) - FIXED"""
        try:
            full_content = f"{email_data.subject} {email_data.body} {email_data.sender}".lower()
            apt_indicators = []
            apt_score = 0.0
            
            # Check for spear-phishing characteristics (ENHANCED)
            for pattern in self.apt_indicators['spear_phishing_patterns']:
                if pattern in full_content:
                    apt_score += 0.5
                    apt_indicators.append(f"Spear-phishing pattern: {pattern}")
            
            # Check for sensitive content keywords
            for pattern in self.apt_indicators['sensitive_content']:
                if pattern in full_content:
                    apt_score += 0.4
                    apt_indicators.append(f"Sensitive content: {pattern}")
            
            # Look for business context indicators
            business_indicators = [
                'quarterly report', 'financial report', 'please review', 'confidential',
                'board meeting', 'strategic', 'merger', 'acquisition', 'due diligence'
            ]
            
            business_count = 0
            for indicator in business_indicators:
                if indicator in full_content:
                    business_count += 1
                    apt_indicators.append(f"Business context: {indicator}")
            
            # Multiple business indicators suggest targeted attack
            if business_count >= 3:
                apt_score += 0.7
            elif business_count >= 2:
                apt_score += 0.5
            elif business_count >= 1:
                apt_score += 0.3
            
            # Check for document attachments (APTs often use documents)
            if email_data.attachments:
                for attachment in email_data.attachments:
                    filename = attachment.get('filename', '').lower()
                    if any(ext in filename for ext in ['.doc', '.pdf', '.xls', '.ppt']):
                        if any(word in filename for word in ['report', 'confidential', 'financial', 'quarterly']):
                            apt_score += 0.4
                            apt_indicators.append(f"Suspicious document: {filename}")
            
            # ML model prediction
            try:
                features = self.vectorizers['email'].transform([full_content])
                ml_proba = self.models['apt'].predict_proba(features)[0]
                ml_score = ml_proba[1] if len(ml_proba) > 1 else 0.0
                apt_score = (apt_score * 0.7) + (ml_score * 0.3)
            except:
                pass
            
            apt_score = min(apt_score, 1.0)
            
            # Generate explanation
            if apt_score >= 0.8:
                risk_level = "CRITICAL APT THREAT"
            elif apt_score >= 0.6:
                risk_level = "HIGH APT RISK"
            elif apt_score >= 0.4:
                risk_level = "MEDIUM APT RISK"
            else:
                risk_level = "LOW APT RISK"
            
            explanation = f"{risk_level} - Business indicators: {business_count}, Total score: {apt_score:.2f}"
            
            return apt_score, explanation, apt_indicators
            
        except Exception as e:
            logger.error(f"APT detection error: {e}")
            return 0.0, f"APT detection error: {str(e)}", []

    def detect_ddos_indicators(self, email_data: EmailData) -> Tuple[float, str, List[str]]:
        """Detect DDoS attack indicators - FIXED"""
        try:
            full_content = f"{email_data.subject} {email_data.body}".lower()
            ddos_indicators = []
            ddos_score = 0.0
            
            # Enhanced DDoS keyword detection
            ddos_keywords = [
                'ddos', 'dos attack', 'denial of service', 'traffic surge', 'bandwidth',
                'server overload', 'connection timeout', 'network congestion',
                'botnet', 'amplification attack', 'syn flood', 'udp flood',
                'massive traffic', 'traffic spike', 'network attack'
            ]
            
            keyword_count = 0
            for keyword in ddos_keywords:
                if keyword in full_content:
                    keyword_count += 1
                    ddos_indicators.append(f"DDoS keyword: {keyword}")
            
            # Score based on keyword density
            if keyword_count >= 3:
                ddos_score += 0.8
            elif keyword_count >= 2:
                ddos_score += 0.6
            elif keyword_count >= 1:
                ddos_score += 0.4
            
            # Check for volumetric attack indicators
            for indicator in self.ddos_patterns['volumetric_indicators']:
                if indicator in full_content:
                    ddos_score += 0.3
                    ddos_indicators.append(f"Volumetric indicator: {indicator}")
            
            # Check for network symptoms
            for symptom in self.ddos_patterns['network_symptoms']:
                if symptom in full_content:
                    ddos_score += 0.3
                    ddos_indicators.append(f"Network symptom: {symptom}")
            
            # Check for botnet signatures
            for botnet in self.ddos_patterns['botnet_signatures']:
                if botnet in full_content:
                    ddos_score += 0.5
                    ddos_indicators.append(f"Botnet signature: {botnet}")
            
            # Look for specific DDoS-related phrases
            ddos_phrases = [
                'massive traffic surge', 'bandwidth exhaustion', 'server response times',
                'connection attempts', 'malicious requests', 'traffic patterns'
            ]
            
            for phrase in ddos_phrases:
                if phrase in full_content:
                    ddos_score += 0.4
                    ddos_indicators.append(f"DDoS phrase: {phrase}")
            
            # ML model prediction
            try:
                features = self.vectorizers['email'].transform([full_content])
                ml_proba = self.models['ddos'].predict_proba(features)[0]
                ml_score = ml_proba[1] if len(ml_proba) > 1 else 0.0
                ddos_score = (ddos_score * 0.7) + (ml_score * 0.3)
            except:
                pass
            
            ddos_score = min(ddos_score, 1.0)
            
            # Generate explanation
            if ddos_score >= 0.7:
                risk_level = "CRITICAL DDOS THREAT"
            elif ddos_score >= 0.5:
                risk_level = "HIGH DDOS RISK"
            elif ddos_score >= 0.3:
                risk_level = "MEDIUM DDOS RISK"
            else:
                risk_level = "LOW DDOS RISK"
            
            explanation = f"{risk_level} - Keywords: {keyword_count}, Score: {ddos_score:.2f}"
            
            return ddos_score, explanation, ddos_indicators
            
        except Exception as e:
            logger.error(f"DDoS detection error: {e}")
            return 0.0, f"DDoS detection error: {str(e)}", []

    def detect_insider_threats(self, email_data: EmailData) -> Tuple[float, str, List[str]]:
        """Detect insider threat indicators - FIXED"""
        try:
            full_content = f"{email_data.subject} {email_data.body}".lower()
            insider_indicators = []
            insider_score = 0.0
            
            # Enhanced data exfiltration detection
            exfiltration_count = 0
            for pattern in self.insider_threat_patterns['data_exfiltration']:
                if pattern in full_content:
                    exfiltration_count += 1
                    insider_indicators.append(f"Data exfiltration: {pattern}")
            
            if exfiltration_count >= 3:
                insider_score += 0.8
            elif exfiltration_count >= 2:
                insider_score += 0.6
            elif exfiltration_count >= 1:
                insider_score += 0.4
            
            # Policy violations
            for violation in self.insider_threat_patterns['policy_violations']:
                if violation in full_content:
                    insider_score += 0.7
                    insider_indicators.append(f"Policy violation: {violation}")
            
            # Behavioral red flags
            behavior_count = 0
            for flag in self.insider_threat_patterns['behavioral_red_flags']:
                if flag in full_content:
                    behavior_count += 1
                    insider_indicators.append(f"Behavioral red flag: {flag}")
            
            if behavior_count >= 2:
                insider_score += 0.6
            elif behavior_count >= 1:
                insider_score += 0.4
            
            # Suspicious requests
            for request in self.insider_threat_patterns['suspicious_requests']:
                if request in full_content:
                    insider_score += 0.6
                    insider_indicators.append(f"Suspicious request: {request}")
            
            # Look for career change + data access combination
            if any(word in full_content for word in ['job', 'career', 'opportunity', 'interview']):
                if any(word in full_content for word in ['backup', 'copy', 'download', 'export', 'access']):
                    insider_score += 0.7
                    insider_indicators.append("Career change + data access combination")
            
            # ML model prediction
            try:
                features = self.vectorizers['email'].transform([full_content])
                ml_proba = self.models['insider_threat'].predict_proba(features)[0]
                ml_score = ml_proba[1] if len(ml_proba) > 1 else 0.0
                insider_score = (insider_score * 0.7) + (ml_score * 0.3)
            except:
                pass
            
            insider_score = min(insider_score, 1.0)
            
            # Generate explanation
            if insider_score >= 0.8:
                risk_level = "CRITICAL INSIDER THREAT"
            elif insider_score >= 0.6:
                risk_level = "HIGH INSIDER THREAT RISK"
            elif insider_score >= 0.4:
                risk_level = "MEDIUM INSIDER THREAT RISK"
            else:
                risk_level = "LOW INSIDER THREAT RISK"
            
            explanation = f"{risk_level} - Indicators: {len(insider_indicators)}, Score: {insider_score:.2f}"
            
            return insider_score, explanation, insider_indicators
            
        except Exception as e:
            logger.error(f"Insider threat detection error: {e}")
            return 0.0, f"Insider threat detection error: {str(e)}", []

    def detect_enhanced_malware(self, email_data: EmailData) -> Tuple[float, str, List[str]]:
        """Enhanced malware detection - FIXED"""
        try:
            malware_indicators = []
            malware_score = 0.0
            full_content = f"{email_data.subject} {email_data.body}".lower()
            
            # Check for ransomware indicators
            ransomware_count = 0
            for indicator in self.malware_signatures['ransomware_indicators']:
                if indicator in full_content:
                    ransomware_count += 1
                    malware_indicators.append(f"Ransomware: {indicator}")
            
            if ransomware_count >= 2:
                malware_score += 0.9
            elif ransomware_count >= 1:
                malware_score += 0.6
            
            # Social engineering malware lures
            social_eng_count = 0
            for pattern in self.malware_signatures['social_engineering']:
                if pattern in full_content:
                    social_eng_count += 1
                    malware_indicators.append(f"Social engineering: {pattern}")
            
            if social_eng_count >= 3:
                malware_score += 0.8
            elif social_eng_count >= 2:
                malware_score += 0.6
            elif social_eng_count >= 1:
                malware_score += 0.4
            
            # Check for trojan patterns
            for pattern in self.malware_signatures['trojan_patterns']:
                if pattern in full_content:
                    malware_score += 0.5
                    malware_indicators.append(f"Trojan: {pattern}")
            
            # Enhanced attachment analysis
            if email_data.attachments:
                for attachment in email_data.attachments:
                    filename = attachment.get('filename', '').lower()
                    
                    # Check for dangerous extensions
                    for ext in self.malware_signatures['malicious_extensions']:
                        if filename.endswith(ext):
                            if ext in ['.exe', '.scr', '.bat']:
                                malware_score = max(malware_score, 0.95)
                                malware_indicators.append(f"CRITICAL: Dangerous executable {ext}")
                            else:
                                malware_score += 0.7
                                malware_indicators.append(f"Suspicious file: {ext}")
                    
                    # Double extension detection
                    if filename.count('.') > 2:
                        malware_score += 0.6
                        malware_indicators.append("Multiple file extensions detected")
                    
                    # Suspicious filename patterns
                    suspicious_names = ['update', 'patch', 'security', 'antivirus', 'cleaner']
                    for name in suspicious_names:
                        if name in filename and any(filename.endswith(ext) for ext in ['.exe', '.scr']):
                            malware_score += 0.8
                            malware_indicators.append(f"Suspicious filename: {filename}")
            
            # ML model prediction
            try:
                features = self.vectorizers['email'].transform([full_content])
                ml_proba = self.models['malware'].predict_proba(features)[0]
                ml_score = ml_proba[1] if len(ml_proba) > 1 else 0.0
                malware_score = (malware_score * 0.7) + (ml_score * 0.3)
            except:
                pass
            
            malware_score = min(malware_score, 1.0)
            
            # Generate explanation
            if malware_score >= 0.85:
                risk_level = "CRITICAL MALWARE THREAT"
            elif malware_score >= 0.7:
                risk_level = "HIGH MALWARE RISK"
            elif malware_score >= 0.5:
                risk_level = "MEDIUM MALWARE RISK"
            else:
                risk_level = "LOW MALWARE RISK"
            
            explanation = f"{risk_level} - Indicators: {len(malware_indicators)}, Score: {malware_score:.2f}"
            
            return malware_score, explanation, malware_indicators
            
        except Exception as e:
            logger.error(f"Enhanced malware detection error: {e}")
            return 0.0, f"Malware detection error: {str(e)}", []
        
    def behavioral_analysis(self, email_data: EmailData) -> Dict[str, float]:
        """Analyze behavioral patterns for anomaly detection"""
        try:
            sender = email_data.sender
            current_time = email_data.timestamp
            
            # Track communication patterns
            if sender not in self.sender_history:
                self.sender_history[sender] = {
                    'email_count': 0,
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'subjects': [],
                    'time_patterns': [],
                    'attachment_behavior': []
                }
            
            profile = self.sender_history[sender]
            profile['email_count'] += 1
            profile['last_seen'] = current_time
            profile['subjects'].append(email_data.subject.lower())
            profile['time_patterns'].append(current_time.hour)
            
            if email_data.attachments:
                profile['attachment_behavior'].append(len(email_data.attachments))
            
            # Behavioral anomaly scoring
            anomaly_score = 0.0
            
            # Frequency anomaly
            time_diff = (current_time - profile['first_seen']).total_seconds()
            if time_diff > 0:
                email_rate = profile['email_count'] / (time_diff / 3600)  # emails per hour
                if email_rate > 10:  # More than 10 emails per hour
                    anomaly_score += 0.6
            
            # Time pattern anomaly
            hour_counts = Counter(profile['time_patterns'])
            if len(hour_counts) == 1 and profile['email_count'] > 5:
                # All emails at same hour - suspicious
                anomaly_score += 0.4
            
            # Subject pattern anomaly
            if len(set(profile['subjects'])) == 1 and profile['email_count'] > 3:
                # Identical subjects - potential spam/attack
                anomaly_score += 0.5
            
            return {
                'frequency_anomaly': min(anomaly_score, 1.0),
                'communication_pattern': len(profile['subjects']) / max(profile['email_count'], 1),
                'time_consistency': len(set(profile['time_patterns'])) / max(len(profile['time_patterns']), 1)
            }
            
        except Exception as e:
            logger.error(f"Behavioral analysis error: {e}")
            return {'frequency_anomaly': 0.0, 'communication_pattern': 0.0, 'time_consistency': 0.0}

    def extract_domain(self, email_or_url: str) -> str:
        """Extract domain from email address or URL"""
        try:
            if '@' in email_or_url:
                return email_or_url.split('@')[-1].lower()
            elif '://' in email_or_url:
                return urlparse(email_or_url).netloc.lower()
            else:
                return email_or_url.lower()
        except:
            return ""

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        return entropy

class EnhancedGmailAPIClient:
    """Enhanced Gmail API client with comprehensive email analysis"""
    
    def __init__(self, credentials_path: str = '/etc/secrets/credentials.json'):
        self.credentials_path = credentials_path
        self.SCOPES = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify'
        ]
        self.service = None
        self.current_account = None
        self.authenticate()
    
    def authenticate(self):
        """Enhanced authentication with error handling"""
        creds = None
        
        if os.path.exists('/etc/secrets/token.json'):
            try:
                creds = Credentials.from_authorized_user_file('/etc/secrets/token.json', self.SCOPES)
            except Exception as e:
                logger.warning(f"Could not load existing token: {e}")
                if os.path.exists('token.json'):
                    os.remove('token.json')
                creds = None
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    logger.error(f"Token refresh failed: {e}")
                    if os.path.exists('token.json'):
                        os.remove('token.json')
                    creds = None
            
        if not creds or not creds.valid:
            raise RuntimeError(
                "Valid Gmail token not available in Render Secret Files."
            )
            
        self.service = build('gmail', 'v1', credentials=creds)
        
        try:
            user_info = self.service.users().getProfile(userId='me').execute()
            self.current_account = user_info.get('emailAddress', 'Connected Gmail')
            logger.info(f"Gmail API authenticated for: {self.current_account}")
        except Exception as e:
            logger.warning(f"Could not get account info: {e}")
            self.current_account = "harshithandata@gmail.com"
    
    def get_messages(self, query: str = '', max_results: int = 100) -> List[Dict]:
        """Get messages with enhanced query options"""
        try:
            # If no query specified, get all recent emails (not just unread)
            if not query:
                query = 'newer_than:7d'  # Get emails from last 7 days
            
            result = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            messages = result.get('messages', [])
            logger.info(f"Retrieved {len(messages)} messages from Gmail")
            return messages
        except Exception as e:
            logger.error(f"Error getting messages: {e}")
            return []
    
    def get_message_details(self, message_id: str) -> Optional[EmailData]:
        """Get detailed message information with enhanced metadata"""
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full'
            ).execute()
                
            return self.parse_message_enhanced(message)
                
        except Exception as e:
            logger.error(f"Error getting message {message_id}: {e}")
            return None
        
    def parse_message_enhanced(self, message: Dict) -> EmailData:
        """Enhanced message parsing with metadata extraction"""
        try:
            headers = {h['name']: h['value'] for h in message['payload'].get('headers', [])}
                
            sender = self.safe_decode(headers.get('From', 'Unknown Sender'))
            subject = self.safe_decode(headers.get('Subject', 'No Subject'))
                
            body = self.extract_body_comprehensive(message['payload'])
            attachments = self.extract_attachments_detailed(message['payload'])
                
            # Extract URLs from content
            urls = self.extract_urls_from_content(f"{subject} {body}")
                
            try:
                timestamp = datetime.fromtimestamp(int(message['internalDate']) / 1000)
            except:
                timestamp = datetime.now()
            
            # Extract enhanced metadata
            sender_ip = self.extract_sender_ip(headers)
            routing_info = self.extract_routing_info(headers)
            auth_results = self.extract_authentication_results(headers)
            
            return EmailData(
                id=message['id'],
                sender=sender,
                subject=subject,
                body=body,
                headers=headers,
                attachments=attachments,
                urls=urls,
                timestamp=timestamp,
                raw_message=message,
                sender_ip=sender_ip,
                routing_info=routing_info,
                authentication_results=auth_results,
                message_size=int(message.get('sizeEstimate', 0)),
                encryption_status=self.check_encryption_status(headers)
            )
                
        except Exception as e:
            logger.error(f"Message parsing error: {e}")
            return None

    def extract_sender_ip(self, headers: Dict) -> str:
        """Extract sender IP from email headers"""
        try:
            received_headers = [v for k, v in headers.items() if k.lower() == 'received']
            for received in received_headers:
                # Look for IP patterns in Received headers
                ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
                match = re.search(ip_pattern, received)
                if match:
                    return match.group(1)
            return ""
        except:
            return ""
    
    def extract_routing_info(self, headers: Dict) -> List[str]:
        """Extract routing information from headers"""
        try:
            routing_info = []
            received_headers = [v for k, v in headers.items() if k.lower() == 'received']
            for received in received_headers[:5]:  # Limit to first 5 hops
                routing_info.append(received[:200])  # Truncate long headers
            return routing_info
        except:
            return []
    
    def extract_authentication_results(self, headers: Dict) -> Dict:
        """Extract email authentication results"""
        try:
            auth_results = {}
            
            if 'Authentication-Results' in headers:
                auth_header = headers['Authentication-Results']
                if 'spf=' in auth_header.lower():
                    spf_match = re.search(r'spf=(\w+)', auth_header.lower())
                    if spf_match:
                        auth_results['spf'] = spf_match.group(1)
                
                if 'dkim=' in auth_header.lower():
                    dkim_match = re.search(r'dkim=(\w+)', auth_header.lower())
                    if dkim_match:
                        auth_results['dkim'] = dkim_match.group(1)
                
                if 'dmarc=' in auth_header.lower():
                    dmarc_match = re.search(r'dmarc=(\w+)', auth_header.lower())
                    if dmarc_match:
                        auth_results['dmarc'] = dmarc_match.group(1)
            
            return auth_results
        except:
            return {}
    
    def check_encryption_status(self, headers: Dict) -> str:
        """Check email encryption status"""
        try:
            received_headers = [v for k, v in headers.items() if k.lower() == 'received']
            for received in received_headers:
                if 'with ESMTPS' in received or 'TLS' in received:
                    return "encrypted"
            return "unencrypted"
        except:
            return "unknown"
    
    def extract_urls_from_content(self, text: str) -> List[str]:
        """Extract URLs from email content"""
        try:
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, text, re.IGNORECASE)
            return urls[:20]  # Limit to first 20 URLs
        except:
            return []
    
    def safe_decode(self, text: str) -> str:
        """Safe text decoding with enhanced error handling"""
        if not text:
            return ""
        try:
            from email.header import decode_header
            decoded_parts = decode_header(text)
            decoded_text = ""
                
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_text += part.decode(encoding, errors='replace')
                    else:
                        decoded_text += part.decode('utf-8', errors='replace')
                else:
                    decoded_text += str(part)
                        
            return decoded_text.strip()
                
        except Exception as e:
            return str(text).encode('utf-8', errors='replace').decode('utf-8')
        
    def extract_body_comprehensive(self, payload: Dict) -> str:
        """Extract email body with enhanced content parsing"""
        try:
            body = ""
                
            if 'parts' in payload:
                for part in payload['parts']:
                    body += self.extract_part_content(part)
                    if len(body) > 10000:  # Increased limit for better analysis
                        break
            else:
                body = self.extract_part_content(payload)
                    
            return body[:10000]  # Increased content limit
                
        except Exception as e:
            logger.error(f"Body extraction error: {e}")
            return "[Error extracting email body]"
        
    def extract_part_content(self, part: Dict) -> str:
        """Extract content from message part with better handling"""
        try:
            mime_type = part.get('mimeType', '')
                
            if not mime_type.startswith('text/'):
                return ""
                    
            body_data = part.get('body', {}).get('data')
            if not body_data:
                return ""
                    
            decoded_bytes = base64.urlsafe_b64decode(body_data)
                
            # Try multiple encodings
            for encoding in ['utf-8', 'latin-1', 'ascii', 'cp1252']:
                try:
                    return decoded_bytes.decode(encoding)
                except UnicodeDecodeError:
                    continue
                        
            return decoded_bytes.decode('utf-8', errors='replace')
                
        except Exception as e:
            return ""
        
    def extract_attachments_detailed(self, payload: Dict) -> List[Dict]:
        """Extract comprehensive attachment information"""
        attachments = []
            
        try:
            def process_parts(parts):
                for part in parts:
                    if 'parts' in part:
                        process_parts(part['parts'])
                    else:
                        filename = part.get('filename')
                        if filename:
                            attachment_info = {
                                'filename': self.safe_decode(filename)[:300],
                                'mimeType': part.get('mimeType', 'unknown'),
                                'size': part.get('body', {}).get('size', 0),
                                'attachment_id': part.get('body', {}).get('attachmentId'),
                                'part_id': part.get('partId'),
                                'headers': part.get('headers', [])
                            }
                            attachments.append(attachment_info)
                                
                            if len(attachments) >= 50:  # Increased limit
                                break
                                    
            if 'parts' in payload:
                process_parts(payload['parts'])
                    
        except Exception as e:
            logger.error(f"Attachment extraction error: {e}")
                
        return attachments
        
    def get_current_account(self) -> str:
        """Get current authenticated account"""
        return self.current_account or "Unknown Account"
        
    def move_to_spam(self, message_id: str) -> bool:
        """Move message to spam"""
        try:
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}
            ).execute()
                
            logger.info(f"Successfully moved message {message_id} to spam")
            return True
                
        except Exception as e:
            logger.error(f"Error moving message to spam: {e}")
            return False

class ComprehensiveThreatDetector:
    """Main threat detector with all enhanced capabilities"""
    
    def __init__(self):
        logger.info("THREAT DETECTION: Initializing comprehensive threat detector...")
        
        self.models = AdvancedThreatDetectionModels()
        self.gmail_client = None
        self.running = False
        
        # Enhanced thresholds for all threat types
        self.critical_threshold = 0.85
        self.high_threshold = 0.7
        self.medium_threshold = 0.5
        self.low_threshold = 0.3
        
        self.alerts = []
        self.processed_emails = set()
        self.statistics = {
            'total_analyzed': 0,
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'low_threats': 0,
            'safe_emails': 0,
            'phishing_detected': 0,
            'malware_detected': 0,
            'apt_detected': 0,
            'ddos_detected': 0,
            'insider_threats_detected': 0,
            'actions_taken': 0
        }
        
        self.init_storage()
        
    def init_storage(self):
        """Initialize enhanced database storage"""
        try:
            os.makedirs('data', exist_ok=True)
            self.db_path = 'data/comprehensive_threat_detection.db'
            self.init_database()
            logger.info("THREAT DETECTION: Enhanced database initialized")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def init_database(self):
        """Initialize enhanced database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comprehensive_threat_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE,
                timestamp TEXT,
                sender TEXT,
                subject TEXT,
                overall_risk REAL,
                phishing_score REAL,
                malware_score REAL,
                apt_score REAL,
                ddos_score REAL,
                insider_threat_score REAL,
                confidence REAL,
                explanation TEXT,
                threat_indicators TEXT,
                actions_taken TEXT,
                email_content TEXT,
                attachment_count INTEGER,
                url_count INTEGER,
                sender_ip TEXT,
                authentication_results TEXT,
                behavioral_analysis TEXT,
                account_email TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_alerts (
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
        
        conn.commit()
        conn.close()
    
    def initialize_gmail(self, credentials_path: str = 'credentials.json'):
        """Initialize enhanced Gmail client"""
        try:
            self.gmail_client = EnhancedGmailAPIClient(credentials_path)
            logger.info(f"Enhanced Gmail client initialized for: {self.gmail_client.get_current_account()}")
        except Exception as e:
            logger.error(f"Failed to initialize Gmail client: {e}")
            raise

    async def analyze_email_comprehensive(self, email_data: EmailData) -> ComprehensiveThreatAnalysis:
        """Comprehensive email analysis for all threat types - FIXED"""
        start_time = time.time()
        
        try:
            logger.info(f"THREAT DETECTION: ==================== COMPREHENSIVE ANALYSIS ====================")
            logger.info(f"THREAT DETECTION: Email ID: {email_data.id}")
            logger.info(f"THREAT DETECTION: Sender: {email_data.sender[:60]}")
            logger.info(f"THREAT DETECTION: Subject: {email_data.subject[:80]}")
            
            # Run all threat detection modules
            phishing_score, phishing_explanation, phishing_indicators = self.models.detect_enhanced_phishing(email_data)
            
            malware_score, malware_explanation, malware_indicators = self.models.detect_enhanced_malware(email_data)
            
            apt_score, apt_explanation, apt_indicators = self.models.detect_advanced_persistent_threats(email_data)
            
            ddos_score, ddos_explanation, ddos_indicators = self.models.detect_ddos_indicators(email_data)
            
            insider_score, insider_explanation, insider_indicators = self.models.detect_insider_threats(email_data)
            
            # Behavioral analysis
            behavioral_metrics = self.models.behavioral_analysis(email_data)
            
            # Calculate comprehensive threat scores
            threat_scores = {
                'phishing': phishing_score,
                'malware': malware_score,
                'apt': apt_score,
                'ddos': ddos_score,
                'insider_threat': insider_score
            }
            
            # FIXED: Better overall risk calculation
            # Take the maximum score as the primary risk indicator
            max_threat_score = max(threat_scores.values())
            
            # Apply weighted scoring for overall risk
            weights = {
                'phishing': 0.25,
                'malware': 0.25,
                'apt': 0.20,
                'ddos': 0.15,
                'insider_threat': 0.15
            }
            
            weighted_score = sum(score * weights[threat_type] for threat_type, score in threat_scores.items())
            
            # Use the higher of max_threat_score or weighted_score
            overall_risk = max(max_threat_score, weighted_score)
            
            # Apply behavioral anomaly boost
            if behavioral_metrics['frequency_anomaly'] > 0.7:
                overall_risk = min(overall_risk + 0.1, 1.0)
            
            # Calculate confidence based on consensus
            scores_array = np.array(list(threat_scores.values()))
            confidence = 1.0 - (np.std(scores_array) / (np.mean(scores_array) + 0.1))
            confidence = max(0.5, min(confidence, 1.0))
            
            # Combine all threat indicators
            all_indicators = (phishing_indicators + malware_indicators + apt_indicators + 
                            ddos_indicators + insider_indicators)
            
            # Generate comprehensive explanation
            explanations = [
                f"Phishing: {phishing_explanation}",
                f"Malware: {malware_explanation}",
                f"APT: {apt_explanation}",
                f"DDoS: {ddos_explanation}",
                f"Insider: {insider_explanation}"
            ]
            
            detailed_explanation = " | ".join(explanations)
            
            processing_time = time.time() - start_time
            
            # Enhanced logging with threat type breakdown
            threat_summary = []
            if phishing_score >= 0.5:
                threat_summary.append(f"PHISHING({phishing_score:.2f})")
                if phishing_score >= 0.7:
                    self.statistics['phishing_detected'] += 1
            if malware_score >= 0.5:
                threat_summary.append(f"MALWARE({malware_score:.2f})")
                if malware_score >= 0.7:
                    self.statistics['malware_detected'] += 1
            if apt_score >= 0.5:
                threat_summary.append(f"APT({apt_score:.2f})")
                if apt_score >= 0.7:
                    self.statistics['apt_detected'] += 1
            if ddos_score >= 0.5:
                threat_summary.append(f"DDOS({ddos_score:.2f})")
                if ddos_score >= 0.7:
                    self.statistics['ddos_detected'] += 1
            if insider_score >= 0.5:
                threat_summary.append(f"INSIDER({insider_score:.2f})")
                if insider_score >= 0.7:
                    self.statistics['insider_threats_detected'] += 1
            
            if overall_risk >= self.critical_threshold:
                logger.error(f"CRITICAL THREAT DETECTED: Risk: {overall_risk:.3f} - Threats: {', '.join(threat_summary)} - {email_data.sender[:40]}")
                self.statistics['critical_threats'] += 1
            elif overall_risk >= self.high_threshold:
                logger.error(f"HIGH THREAT DETECTED: Risk: {overall_risk:.3f} - Threats: {', '.join(threat_summary)} - {email_data.sender[:40]}")
                self.statistics['high_threats'] += 1
            elif overall_risk >= self.medium_threshold:
                logger.warning(f"MEDIUM THREAT DETECTED: Risk: {overall_risk:.3f} - Threats: {', '.join(threat_summary)} - {email_data.sender[:40]}")
                self.statistics['medium_threats'] += 1
            elif overall_risk >= self.low_threshold:
                logger.info(f"LOW THREAT DETECTED: Risk: {overall_risk:.3f} - {email_data.sender[:40]}")
                self.statistics['low_threats'] += 1
            else:
                logger.info(f"EMAIL SAFE: Risk: {overall_risk:.3f} - {email_data.sender[:40]}")
                self.statistics['safe_emails'] += 1
                
            self.statistics['total_analyzed'] += 1
            
            logger.info(f"THREAT DETECTION: Comprehensive analysis complete - Processing time: {processing_time:.3f}s")
            
            return ComprehensiveThreatAnalysis(
                email_id=email_data.id,
                threat_types=threat_scores,
                overall_risk=overall_risk,
                confidence=confidence,
                explanation=detailed_explanation,
                timestamp=datetime.now(),
                actions_taken=[],
                sender=email_data.sender,
                subject=email_data.subject,
                email_content=email_data.body[:1500],
                threat_indicators=all_indicators,
                apt_indicators=apt_indicators,
                ddos_indicators=ddos_indicators,
                insider_threat_score=insider_score,
                behavioral_anomalies=[f"Frequency anomaly: {behavioral_metrics['frequency_anomaly']:.2f}"],
                network_indicators={'sender_ip': email_data.sender_ip, 'auth_status': str(email_data.authentication_results)},
                email_metadata={'size': email_data.message_size, 'encryption': email_data.encryption_status}
            )
            
        except Exception as e:
            logger.error(f"THREAT DETECTION: Comprehensive analysis error: {e}")
            return ComprehensiveThreatAnalysis(
                email_id=email_data.id,
                threat_types={},
                overall_risk=0.0,
                confidence=0.0,
                explanation=f"Analysis error: {str(e)[:100]}",
                timestamp=datetime.now(),
                actions_taken=[],
                sender=email_data.sender,
                subject=email_data.subject,
                email_content="",
                threat_indicators=[]
            )

    async def take_comprehensive_action(self, email_data: EmailData, analysis: ComprehensiveThreatAnalysis):
        """Take comprehensive actions based on all threat types"""
        actions_taken = []
        
        try:
            current_account = self.gmail_client.get_current_account() if self.gmail_client else "Unknown"
            
            # Critical threat response
            if analysis.overall_risk >= self.critical_threshold:
                logger.error(f"CRITICAL COMPREHENSIVE THREAT: {email_data.id} - Risk: {analysis.overall_risk:.3f}")
                
                # Immediate quarantine
                if self.gmail_client.move_to_spam(email_data.id):
                    actions_taken.append("quarantined_immediately")
                
                # Generate critical alert
                await self.send_comprehensive_alert(email_data, analysis, "CRITICAL")
                actions_taken.append("critical_alert_sent")
                
                # APT-specific actions
                if analysis.threat_types.get('apt', 0) >= 0.8:
                    actions_taken.append("apt_response_initiated")
                    logger.error(f"APT RESPONSE: Potential advanced persistent threat detected from {email_data.sender}")
                
                # Insider threat actions
                if analysis.threat_types.get('insider_threat', 0) >= 0.8:
                    actions_taken.append("insider_investigation_flagged")
                    logger.error(f"INSIDER THREAT: Employee behavior flagged for investigation")
                
                # DDoS response
                if analysis.threat_types.get('ddos', 0) >= 0.8:
                    actions_taken.append("ddos_mitigation_triggered")
                    logger.error(f"DDOS RESPONSE: Attack indicators detected, mitigation protocols engaged")
                
            elif analysis.overall_risk >= self.high_threshold:
                logger.warning(f"HIGH COMPREHENSIVE THREAT: {email_data.id} - Risk: {analysis.overall_risk:.3f}")
                
                await self.send_comprehensive_alert(email_data, analysis, "HIGH")
                actions_taken.append("high_alert_sent")
                
                # Enhanced monitoring for high-risk threats
                actions_taken.append("enhanced_monitoring_enabled")
                
            elif analysis.overall_risk >= self.medium_threshold:
                logger.info(f"MEDIUM COMPREHENSIVE THREAT: {email_data.id} - Risk: {analysis.overall_risk:.3f}")
                
                await self.send_comprehensive_alert(email_data, analysis, "MEDIUM")
                actions_taken.append("medium_alert_sent")
            
            # Always log behavioral anomalies
            if analysis.behavioral_anomalies:
                actions_taken.append("behavioral_pattern_logged")
            
            if actions_taken:
                self.statistics['actions_taken'] += 1
                
            analysis.actions_taken = actions_taken
            await self.store_comprehensive_analysis(analysis, email_data)
            
        except Exception as e:
            logger.error(f"THREAT DETECTION: Comprehensive action error for {email_data.id}: {e}")

    async def send_comprehensive_alert(self, email_data: EmailData, analysis: ComprehensiveThreatAnalysis, priority: str):
        """Send comprehensive threat alert"""
        try:
            # Determine primary threat types
            primary_threats = []
            for threat_type, score in analysis.threat_types.items():
                if score >= 0.5:
                    primary_threats.append(f"{threat_type.upper()}({score:.2f})")
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'priority': priority,
                'email_id': email_data.id,
                'sender': email_data.sender[:100],
                'subject': email_data.subject[:150],
                'overall_risk': analysis.overall_risk,
                'threat_breakdown': analysis.threat_types,
                'primary_threats': primary_threats,
                'explanation': analysis.explanation[:500],
                'threat_indicators': analysis.threat_indicators[:15] if analysis.threat_indicators else [],
                'apt_indicators': analysis.apt_indicators[:10] if analysis.apt_indicators else [],
                'ddos_indicators': analysis.ddos_indicators[:10] if analysis.ddos_indicators else [],
                'behavioral_anomalies': analysis.behavioral_anomalies[:5] if analysis.behavioral_anomalies else [],
                'network_indicators': analysis.network_indicators,
                'actions_taken': analysis.actions_taken,
                'account_email': self.gmail_client.get_current_account() if self.gmail_client else "Unknown"
            }
            
            self.alerts.append(alert)
            if len(self.alerts) > 200:  # Increased alert history
                self.alerts = self.alerts[-200:]
            
            # Enhanced logging based on threat types
            if 'APT' in [t.split('(')[0] for t in primary_threats]:
                logger.error(f"APT ALERT: Advanced Persistent Threat - {email_data.sender[:40]} - Risk: {analysis.overall_risk:.3f}")
            if 'DDOS' in [t.split('(')[0] for t in primary_threats]:
                logger.error(f"DDOS ALERT: Distributed Denial of Service indicators - Risk: {analysis.overall_risk:.3f}")
            if 'INSIDER_THREAT' in [t.split('(')[0] for t in primary_threats]:
                logger.error(f"INSIDER ALERT: Internal threat detected - {email_data.sender[:40]}")
            
            logger.info(f"{priority} COMPREHENSIVE ALERT: {', '.join(primary_threats)} - {email_data.sender[:40]}")
            
        except Exception as e:
            logger.error(f"Comprehensive alert error: {e}")

    async def store_comprehensive_analysis(self, analysis: ComprehensiveThreatAnalysis, email_data: EmailData):
        """Store comprehensive analysis results"""
        try:
            current_account = self.gmail_client.get_current_account() if self.gmail_client else "Unknown"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO comprehensive_threat_analysis 
                (email_id, timestamp, sender, subject, overall_risk, 
                 phishing_score, malware_score, apt_score, ddos_score, insider_threat_score,
                 confidence, explanation, threat_indicators, actions_taken, email_content,
                 attachment_count, url_count, sender_ip, authentication_results, 
                 behavioral_analysis, account_email)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis.email_id, analysis.timestamp.isoformat(),
                email_data.sender[:150], email_data.subject[:300],
                analysis.overall_risk,
                analysis.threat_types.get('phishing', 0),
                analysis.threat_types.get('malware', 0),
                analysis.threat_types.get('apt', 0),
                analysis.threat_types.get('ddos', 0),
                analysis.threat_types.get('insider_threat', 0),
                analysis.confidence, analysis.explanation[:1000],
                json.dumps(analysis.threat_indicators),
                json.dumps(analysis.actions_taken),
                email_data.body[:2000],
                len(email_data.attachments), len(email_data.urls),
                email_data.sender_ip,
                json.dumps(email_data.authentication_results),
                json.dumps(analysis.behavioral_anomalies),
                current_account
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Comprehensive storage error: {e}")

    async def monitor_emails_comprehensive(self):
        """Comprehensive email monitoring with enhanced capabilities"""
        self.running = True
        current_account = self.gmail_client.get_current_account() if self.gmail_client else "Unknown"
        
        logger.info("=" * 80)
        logger.info("THREAT DETECTION: STARTING COMPREHENSIVE EMAIL MONITORING")
        logger.info(f"THREAT DETECTION: Account: {current_account}")
        logger.info(f"THREAT DETECTION: Monitoring: Phishing, Malware, APT, DDoS, Insider Threats")
        logger.info(f"THREAT DETECTION: Thresholds - Critical: {self.critical_threshold}, High: {self.high_threshold}")
        logger.info("=" * 80)
        
        cycle_count = 0
        
        while self.running:
            try:
                cycle_count += 1
                logger.info(f"THREAT DETECTION: Starting comprehensive monitoring cycle #{cycle_count}")
                
                if not self.gmail_client or not self.gmail_client.service:
                    logger.error("Gmail client not initialized")
                    await asyncio.sleep(30)
                    continue
                
                # Get more emails for comprehensive analysis
                messages = self.gmail_client.get_messages(query='', max_results=100)
                
                if not messages:
                    logger.info("No messages found for analysis")
                    await asyncio.sleep(30)
                    continue
                
                processed_count = 0
                threats_found = 0
                threat_breakdown = {'phishing': 0, 'malware': 0, 'apt': 0, 'ddos': 0, 'insider': 0}
                
                for message in messages:
                    if not self.running:
                        break
                        
                    try:
                        email_id = message['id']
                        
                        if email_id in self.processed_emails:
                            continue
                            
                        email_data = self.gmail_client.get_message_details(email_id)
                        
                        if email_data:
                            analysis = await self.analyze_email_comprehensive(email_data)
                            
                            # Take action for any significant threat
                            if analysis.overall_risk >= self.low_threshold:
                                await self.take_comprehensive_action(email_data, analysis)
                                
                                if analysis.overall_risk >= self.medium_threshold:
                                    threats_found += 1
                                    
                                    # Count specific threat types
                                    for threat_type, score in analysis.threat_types.items():
                                        if score >= 0.5:
                                            if threat_type == 'phishing':
                                                threat_breakdown['phishing'] += 1
                                            elif threat_type == 'malware':
                                                threat_breakdown['malware'] += 1
                                            elif threat_type == 'apt':
                                                threat_breakdown['apt'] += 1
                                            elif threat_type == 'ddos':
                                                threat_breakdown['ddos'] += 1
                                            elif threat_type == 'insider_threat':
                                                threat_breakdown['insider'] += 1
                            
                            self.processed_emails.add(email_id)
                            processed_count += 1
                            
                            # Enhanced logging with threat breakdown
                            risk_level = self.get_risk_level(analysis.overall_risk)
                            threat_types = [k for k, v in analysis.threat_types.items() if v >= 0.5]
                            threat_summary = f"[{'+'.join(threat_types).upper()}]" if threat_types else ""
                            
                            logger.info(f"PROCESSED [{risk_level}]{threat_summary}: {email_data.sender[:30]} - {email_data.subject[:50]} (Risk: {analysis.overall_risk:.3f})")
                            
                            if processed_count >= 50:  # Increased processing limit
                                break
                                
                    except Exception as e:
                        logger.error(f"Error processing message {message.get('id', 'unknown')}: {e}")
                        continue
                
                # Enhanced cycle summary
                if threat_breakdown['apt'] > 0:
                    logger.error(f"APT THREATS DETECTED: {threat_breakdown['apt']} Advanced Persistent Threats found")
                if threat_breakdown['ddos'] > 0:
                    logger.error(f"DDOS INDICATORS: {threat_breakdown['ddos']} DDoS-related threats detected")
                if threat_breakdown['insider'] > 0:
                    logger.error(f"INSIDER THREATS: {threat_breakdown['insider']} insider threat indicators found")
                
                logger.info(f"Cycle #{cycle_count} complete: {processed_count} processed, {threats_found} threats")
                logger.info(f"Threat breakdown: Phishing({threat_breakdown['phishing']}), Malware({threat_breakdown['malware']}), APT({threat_breakdown['apt']}), DDoS({threat_breakdown['ddos']}), Insider({threat_breakdown['insider']})")
                
                await asyncio.sleep(20)  # Reduced sleep for more responsive monitoring
                
            except Exception as e:
                logger.error(f"Comprehensive monitoring error: {e}")
                await asyncio.sleep(60)

    def get_comprehensive_statistics(self) -> Dict:
        """Get comprehensive statistics including all threat types"""
        try:
            current_account = self.gmail_client.get_current_account() if self.gmail_client else "Unknown"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get comprehensive threat counts
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE account_email = ?", (current_account,))
            total_analyzed = cursor.fetchone()[0]
            
            # Risk level counts
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE overall_risk >= ? AND account_email = ?", 
                         (self.critical_threshold, current_account))
            critical_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE overall_risk >= ? AND overall_risk < ? AND account_email = ?", 
                         (self.high_threshold, self.critical_threshold, current_account))
            high_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE overall_risk >= ? AND overall_risk < ? AND account_email = ?", 
                         (self.medium_threshold, self.high_threshold, current_account))
            medium_count = cursor.fetchone()[0]
            
            # Individual threat type counts
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE phishing_score > 0.5 AND account_email = ?", (current_account,))
            phishing_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE malware_score > 0.5 AND account_email = ?", (current_account,))
            malware_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE apt_score > 0.5 AND account_email = ?", (current_account,))
            apt_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE ddos_score > 0.5 AND account_email = ?", (current_account,))
            ddos_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM comprehensive_threat_analysis WHERE insider_threat_score > 0.5 AND account_email = ?", (current_account,))
            insider_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_analyzed": total_analyzed,
                "risk_levels": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "safe": max(0, total_analyzed - critical_count - high_count - medium_count)
                },
                "threat_types": {
                    "phishing": phishing_count,
                    "malware": malware_count,
                    "apt": apt_count,
                    "ddos": ddos_count,
                    "insider_threats": insider_count
                },
                "current_account": current_account,
                "monitoring_active": self.running,
                "session_stats": self.statistics,
                "comprehensive_capabilities": [
                    "Advanced Phishing Detection",
                    "Enhanced Malware Analysis", 
                    "APT (Advanced Persistent Threats)",
                    "DDoS Attack Indicators",
                    "Insider Threat Detection",
                    "Behavioral Anomaly Analysis",
                    "Business Email Compromise (BEC)",
                    "Spear-phishing Detection"
                ]
            }
            
        except Exception as e:
            logger.error(f"Comprehensive statistics error: {e}")
            return {"error": str(e)}

    def get_risk_level(self, risk_score: float) -> str:
        """Get risk level text"""
        if risk_score >= self.critical_threshold:
            return "CRITICAL"
        elif risk_score >= self.high_threshold:
            return "HIGH"
        elif risk_score >= self.medium_threshold:
            return "MEDIUM"
        elif risk_score >= self.low_threshold:
            return "LOW"
        else:
            return "SAFE"

    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        logger.info("THREAT DETECTION: Monitoring stopped")

# Production API with Flask dashboard
class ProductionThreatAPI:
    """Production threat detection API with comprehensive dashboard"""
    
    def __init__(self, detector: ComprehensiveThreatDetector):
        self.detector = detector
        self.app = Flask(__name__)
        self.setup_routes()
        
    def setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/', methods=['GET'])
        def dashboard():
            """Serve enhanced production dashboard"""
            try:
                with open('production_dashboard.html', 'r', encoding='utf-8') as f:
                    return f.read()
            except FileNotFoundError:
                return self.generate_minimal_dashboard()
        
        @self.app.route('/health', methods=['GET'])
        def health():
            """System health check"""
            account_info = self.detector.gmail_client.get_current_account() if self.detector.gmail_client else "Unknown"
            
            return jsonify({
                "status": "healthy" if self.detector.gmail_client else "disconnected",
                "timestamp": datetime.now().isoformat(),
                "current_account": account_info,
                "emails_processed": len(self.detector.processed_emails),
                "alerts_count": len(self.detector.alerts),
                "monitoring_active": self.detector.running,
                "capabilities": [
                    "Enhanced Phishing Detection",
                    "APT Detection", 
                    "Insider Threat Analysis",
                    "DDoS Indicators",
                    "Malware Analysis",
                    "Behavioral Monitoring"
                ]
            })
        
        @self.app.route('/statistics', methods=['GET'])
        def get_statistics():
            """Get comprehensive statistics"""
            return jsonify(self.detector.get_comprehensive_statistics())
        
        @self.app.route('/alerts', methods=['GET'])
        def get_alerts():
            """Get threat alerts"""
            try:
                limit = request.args.get('limit', 50, type=int)
                priority = request.args.get('priority', 'all')
                
                alerts = self.detector.alerts.copy()
                
                if priority != 'all':
                    alerts = [a for a in alerts if a.get('priority', '').lower() == priority.lower()]
                
                alerts = alerts[-limit:]
                alerts.reverse()
                
                return jsonify({
                    "alerts": alerts,
                    "total_count": len(self.detector.alerts),
                    "filtered_count": len(alerts)
                })
                
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/all-analysis', methods=['GET'])
        def get_all_analysis():
            """Get all analyzed emails"""
            try:
                limit = request.args.get('limit', 100, type=int)
                min_risk = request.args.get('min_risk', 0.0, type=float)
                current_account = self.detector.gmail_client.get_current_account() if self.detector.gmail_client else "Unknown"
                
                conn = sqlite3.connect(self.detector.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT email_id, timestamp, sender, subject, overall_risk, 
                           phishing_score, malware_score, apt_score, ddos_score, insider_threat_score,
                           explanation, threat_indicators, actions_taken, 
                           attachment_count, url_count
                    FROM comprehensive_threat_analysis 
                    WHERE account_email = ? AND overall_risk >= ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (current_account, min_risk, limit))
                
                results = cursor.fetchall()
                conn.close()
                
                analysis_data = []
                for row in results:
                    risk_score = row[4]
                    analysis_data.append({
                        'email_id': row[0],
                        'timestamp': row[1],
                        'sender': row[2],
                        'subject': row[3],
                        'risk_score': risk_score,
                        'threat_types': {
                            'phishing': row[5],
                            'malware': row[6],
                            'apt': row[7],
                            'ddos': row[8],
                            'insider_threat': row[9]
                        },
                        'explanation': row[10],
                        'threat_indicators': json.loads(row[11]) if row[11] else [],
                        'actions_taken': json.loads(row[12]) if row[12] else [],
                        'attachment_count': row[13],
                        'url_count': row[14],
                        'priority': self.get_risk_level_text(risk_score),
                        'risk_class': self.get_risk_class(risk_score)
                    })
                
                return jsonify({
                    "analysis": analysis_data,
                    "total_count": len(analysis_data),
                    "account": current_account
                })
                
            except Exception as e:
                logger.error(f"All analysis error: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/analyze', methods=['POST'])
        def analyze_email():
            """Analyze email manually for testing"""
            try:
                data = request.json
                
                email_data = EmailData(
                    id=data.get('id', f'manual_{int(time.time())}'),
                    sender=data.get('sender', 'test@example.com'),
                    subject=data.get('subject', 'Test Email'),
                    body=data.get('body', ''),
                    headers=data.get('headers', {}),
                    attachments=data.get('attachments', []),
                    urls=data.get('urls', []),
                    timestamp=datetime.now()
                )
                
                # Run comprehensive analysis
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                analysis = loop.run_until_complete(self.detector.analyze_email_comprehensive(email_data))
                
                return jsonify({
                    "email_id": analysis.email_id,
                    "overall_risk": analysis.overall_risk,
                    "confidence": analysis.confidence,
                    "threat_types": analysis.threat_types,
                    "explanation": analysis.explanation,
                    "threat_indicators": analysis.threat_indicators,
                    "apt_indicators": analysis.apt_indicators,
                    "ddos_indicators": analysis.ddos_indicators,
                    "insider_threat_score": analysis.insider_threat_score,
                    "timestamp": analysis.timestamp.isoformat(),
                    "risk_level": self.get_risk_level_text(analysis.overall_risk),
                    "recommended_actions": self.get_recommended_actions(analysis.overall_risk)
                })
                
            except Exception as e:
                logger.error(f"Manual analysis error: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/start', methods=['POST'])
        def start_monitoring():
            """Start monitoring"""
if not self.detector.running:
    if not self.detector.gmail_client:
        try:
            self.detector.initialize_gmail('/etc/secrets/credentials.json')
        except Exception as e:
            logger.error(f"Gmail initialization failed: {e}")
            return jsonify({
                "status": "error",
                "message": f"Gmail initialization failed: {e}"
            }), 500

    threading.Thread(target=self.run_monitoring, daemon=True).start()
    return jsonify({
        "status": "success",
        "message": "Enhanced monitoring started"
    })
            else:
                return jsonify({"status": "info", "message": "Already running"})
        
        @self.app.route('/stop', methods=['POST'])
        def stop_monitoring():
            """Stop monitoring"""
            self.detector.stop_monitoring()
            return jsonify({"status": "success", "message": "Monitoring stopped"})

    def generate_minimal_dashboard(self):
        """Generate minimal dashboard if HTML file not found"""
        return """
        <!DOCTYPE html>
        <html><head><title>Enhanced Threat Detection</title></head>
        <body>
        <h1>Enhanced Gmail Threat Detection System</h1>
        <p>Dashboard file not found. System is running with basic interface.</p>
        <p>API Endpoints:</p>
        <ul>
        <li>/health - System health</li>
        <li>/statistics - Threat statistics</li>
        <li>/alerts - Threat alerts</li>
        <li>/all-analysis - Analysis results</li>
        </ul>
        </body></html>
        """
    
    def get_risk_level_text(self, risk_score: float) -> str:
        """Get risk level text"""
        if risk_score >= 0.85:
            return "CRITICAL"
        elif risk_score >= 0.7:
            return "HIGH"
        elif risk_score >= 0.5:
            return "MEDIUM"
        elif risk_score >= 0.3:
            return "LOW"
        else:
            return "SAFE"
    
    def get_risk_class(self, risk_score: float) -> str:
        """Get CSS class for risk level"""
        if risk_score >= 0.85:
            return "critical"
        elif risk_score >= 0.7:
            return "high"
        elif risk_score >= 0.5:
            return "medium"
        elif risk_score >= 0.3:
            return "low"
        else:
            return "safe"
    
    def get_recommended_actions(self, risk_score: float) -> List[str]:
        """Get recommended actions"""
        if risk_score >= 0.85:
            return ["Immediate quarantine", "Block sender", "Report to security", "Alert users", "Investigate APT indicators"]
        elif risk_score >= 0.7:
            return ["Move to spam", "Flag for review", "Monitor sender", "Enhanced analysis"]
        elif risk_score >= 0.5:
            return ["Monitor closely", "User notification", "Behavioral tracking"]
        elif risk_score >= 0.3:
            return ["Log and monitor", "Pattern analysis"]
        else:
            return ["No action needed"]
    
    def run_monitoring(self):
        """Run monitoring in background"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.detector.monitor_emails_comprehensive())
    
    def run(self, host='127.0.0.1', port=8888, debug=False):
        """Run the API server"""
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Enhanced main function with comprehensive capabilities"""
    print("\n" + "=" * 90)
    print("COMPREHENSIVE GMAIL CYBERSECURITY THREAT DETECTION SYSTEM")
    print("Advanced AI-Powered Detection: Phishing | Malware | APT | DDoS | Insider Threats")
    print("=" * 90)
    
    try:
        print("\nInitializing comprehensive threat detection system...")
        detector = ComprehensiveThreatDetector()
        
        print("Setting up enhanced Gmail API connection...")
        detector.initialize_gmail('credentials.json')
        
        print("Starting comprehensive monitoring system...")
        
        print("\nComprehensive Threat Detection System Ready!")
        print(f"Connected to Gmail account: {detector.gmail_client.get_current_account()}")
        
        print(f"\nThreat Detection Capabilities:")
        print(f"   ✓ Advanced Phishing Detection (BEC, Spear-phishing)")
        print(f"   ✓ Enhanced Malware Analysis (Ransomware, Trojans)")
        print(f"   ✓ APT (Advanced Persistent Threats) Detection")
        print(f"   ✓ DDoS Attack Indicators")
        print(f"   ✓ Insider Threat Detection")
        print(f"   ✓ Behavioral Anomaly Analysis")
        
        print(f"\nRisk Thresholds:")
        print(f"   Critical: {detector.critical_threshold} (immediate action)")
        print(f"   High: {detector.high_threshold} (alert and investigate)")
        print(f"   Medium: {detector.medium_threshold} (monitor closely)")
        
        print("\nStarting real-time comprehensive monitoring...")
        threading.Thread(
            target=lambda: asyncio.run(detector.monitor_emails_comprehensive()), 
            daemon=True
        ).start()
        
        print("\n" + "=" * 90)
        print("COMPREHENSIVE THREAT DETECTION SYSTEM ACTIVE")
        print("Now monitoring all email traffic for advanced cyber threats...")
        print("=" * 90)
        
        print("\nPress Ctrl+C to stop the system...")
        
        # Start API server
        api = ProductionThreatAPI(detector)
        print(f"\nAPI Dashboard available at: http://localhost:8888")
        api.run(host='127.0.0.1', port=8888, debug=False)
        
    except KeyboardInterrupt:
        print("\nShutting down comprehensive system...")
        if 'detector' in locals():
            detector.running = False
        print("System stopped safely")
        
    except Exception as e:
        print(f"\nSystem error: {e}")
        print("\nEnsure you have:")
        print("1. Gmail API credentials in 'credentials.json'")
        print("2. Required dependencies installed:")
        print("   pip install numpy pandas scikit-learn nltk textblob python-whois")
        print("   pip install google-auth-oauthlib google-api-python-client flask")
        print("3. Proper file permissions")

if __name__ == "__main__":
    main()    
