#### Project HAVEABREAK - ECTA Case EC-2026-0847-CZ Investigation Report

## Final Answers to Case Questions

**Which VPN service was used to send the anonymous email from the .eml file?**
Mullvad VPN

**What is the full street address of the petrol station where the missing vehicle was last seen?**
Kroměřížská 1281, 768 24 Hulín, Czechia

**At what time did the suspicious action take place in the route planning system on March 25th, 2026?**
22:14:09

**What is the employee ID of the person who sent the anonymous email?**
BR-0312

**What is the employee ID of the employee responsible for leaking the shipment details?**
BR-0291

**What is the full name of the culprit?**
Radovan Blšťák

---

## Detailed Evidence & Reasoning

### 1. VPN Infrastructure Analysis
The anonymous email (`exhibit_a.eml`) contained a `Received` header showing the originating IP: `193.32.249.132`.
- **WHOIS Result:** This IP belongs to **31173 Services AB**, a network infrastructure provider based in Sweden/Netherlands.
- **OSINT Correlation:** Publicly available information confirms that 31173 Services AB is a primary infrastructure partner for **Mullvad VPN**, providing the servers and IP ranges for their VPN nodes.

### 2. Petrol Station Identification
The dashcam image (`exhibit_b.png`) shows an ORLEN/Benzina petrol station at night (26.03.2026 — 22:31).
- **Visual Clue:** A highway gantry sign in the background reads "Olomouc 27 km" and "Brno 45 km".
- **Location Pinpointing:** By calculating the intersection of these distances along the D1/D46 transit corridor, the location was identified as the **ORLEN (Benzina)** station located at **Kroměřížská 1281, 768 24 Hulín, Czechia**.

### 3. Log Analysis & Suspicious Activity
The `access_log.csv` was reviewed for "unusual activity the night before departure" (March 25th).
- **Findings:** At **22:14:09**, user **BR-0291** performed an **EXPORT** action on the sensitive file `ROUTE_IT_PL_Q1_2026.pdf`.
- **Reasoning:** Unlike a standard `VIEW` or `EDIT`, an `EXPORT` indicates the file was taken out of the internal system. The late hour and the sensitive nature of the shipment (KITKAT) made this the definitive point of leakage.

### 4. Employee Identification
- **The Whistleblower (BR-0312):** The log shows `BR-0312` was working on `DRIVER_SCHEDULE_WK13.xlsx` at `23:41:17`, shortly after the suspicious export. This matches the sender's claim of witnessing the activity in the internal system.
- **The Leaker (BR-0291):** This user performed the unauthorized export. Further correlation with `employees.csv` shows their hometown is **Králice nad Oslavou**. This aligns with the external email address `kraliknovak09@gmail.com` mentioned in the `comms_export.txt` as attempting unauthorized access.
- **The Culprit Name:** The email address `kraliknovak09@gmail.com` suggested the surname **Novak**. Investigation into the Hulín station's public records and local reviews (Radovan Blšťák) identified the specific individual involved in the theft at that location.