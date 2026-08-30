from gmail_threat_detector import ComprehensiveThreatDetector, ProductionThreatAPI

detector = ComprehensiveThreatDetector()
detector.initialize_gmail('/etc/secrets/credentials.json')
api = ProductionThreatAPI(detector)

app = api.app
