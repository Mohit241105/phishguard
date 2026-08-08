import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import FeatureUnion

class MLEngine:
    """TF-IDF + Random Forest Machine Learning phishing detection model."""

    _instance = None

    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self._is_trained = False
        self._train_baseline_model()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _train_baseline_model(self):
        """Trains an embedded baseline machine learning model on representative phishing & safe text corpora."""
        phishing_samples = [
            "Urgent: Your account has been suspended due to unauthorized login. Click here to verify your password immediately.",
            "Dear Customer, your bank statement is ready. Please sign in to update payment details and avoid account locking.",
            "Final Notice: Unpaid invoice #9821. Wire transfer funds within 24 hours to prevent legal action.",
            "Security Alert: Someone accessed your Microsoft account from an unknown IP address. Confirm your identity now.",
            "Payroll Change Request: Please review attached direct deposit update document and reply urgently.",
            "PayPal Security: We detected suspicious activity. Re-authenticate your credential details to unblock your account.",
            "DocuSign: You have received a confidential document. Login with your email password to sign.",
            "Your Netflix subscription has expired. Update credit card information immediately or access will be revoked.",
            "Apple ID Alert: Your account was used to purchase an iPhone. If this wasn't you, click the link to cancel.",
            "Important CEO Request: Are you at your desk? I need you to purchase gift cards for a confidential client meeting."
        ]

        safe_samples = [
            "Hi John, please find the weekly project status report attached for your review. Let me know if you have questions.",
            "Team meeting reminder: We will be discussing the Q3 roadmap tomorrow at 10 AM in Conference Room B.",
            "Thank you for attending the engineering webinar. The slides and recording link are attached.",
            "Hey Sarah, here is the updated code pull request. All unit tests passed successfully.",
            "Quarterly newsletter: Highlights from our product update, community news, and upcoming developer events.",
            "Flight booking confirmation: Your flight to San Francisco is confirmed for August 15. See itinerary inside.",
            "Receipt for your coffee purchase. Total: $4.50. Thank you for visiting local roast cafe.",
            "System maintenance notice: Scheduled maintenance on the internal staging environment this Sunday from 2 AM to 4 AM.",
            "Welcome to the team! Here is your onboarding checklist and links to internal documentation wiki.",
            "Lunch order details for Friday pizza party. Please select your preference by end of day."
        ]

        texts = phishing_samples + safe_samples
        labels = [1] * len(phishing_samples) + [0] * len(safe_samples)  # 1 = Phishing, 0 = Safe

        X_tfidf = self.vectorizer.fit_transform(texts)
        self.model.fit(X_tfidf, labels)
        self._is_trained = True

    def predict(self, parsed_email: dict, header_score: int = 0, url_score: int = 0) -> dict:
        text = parsed_email.get("subject", "") + " " + parsed_email.get("combined_body", "")
        if not text.strip():
            text = "empty body"

        X_test = self.vectorizer.transform([text])
        probs = self.model.predict_proba(X_test)[0]
        
        # probs[1] is probability of Phishing (0.0 to 1.0)
        phishing_prob = float(probs[1]) if len(probs) > 1 else 0.5
        safe_prob = float(probs[0]) if len(probs) > 0 else 0.5

        # Feature boost if header or URL score is extremely high
        if header_score > 60 or url_score > 60:
            phishing_prob = min(1.0, phishing_prob + 0.20)
            safe_prob = max(0.0, 1.0 - phishing_prob)

        ml_score = int(phishing_prob * 100)

        if ml_score >= 65:
            classification = "PHISHING"
        elif ml_score >= 35:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        return {
            "ml_risk_score": ml_score,
            "classification": classification,
            "phishing_probability": round(phishing_prob * 100, 1),
            "safe_probability": round(safe_prob * 100, 1),
            "confidence": round(max(phishing_prob, safe_prob) * 100, 1)
        }
