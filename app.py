from gmail_threat_detector import ComprehensiveThreatDetector, ProductionThreatAPI

detector = ComprehensiveThreatDetector()
api = ProductionThreatAPI(detector)

app = api.app
