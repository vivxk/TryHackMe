
An AI assistant has three open vulnerabilities. Find them. Fix them. Prove the system is secure.

#### Your Mission
You are a security engineer at Meridian Security Group. The company deployed an internal AI assistant, Bastion, to help employees with policy questions and operational issues.  

A routine audit flagged three security vulnerabilities in Bastion's configuration. Your job is to confirm each vulnerability exists, diagnose the root cause, and prescribe the correct remediation. Bastion will only accept a fix if you describe the right control. Vague answers get rejected.

#### Your Set Up
You have direct access to Bastion through the chat window on this page. You are logged in as a security administrator.  
  
Start by querying Bastion to understand what data it serves and whether it enforces access boundaries. Use `SHOW LOGS` to inspect logging behaviour. Use `QUERY AS: [any name]` to test tenant isolation.  
When you find a vulnerability, describe the specific security control that would fix it. If your description is accurate, Bastion will apply the fix and reveal a flag fragment. There are three vulnerabilities and three fragments. Combine them to get the complete flag.  
  
Check your progress at any time with `STATUS`.

---

## Audit Dialogue

> 👋 **Hey there!**  
> *This agent is playing a role, can you achieve your goal?*

**User:**
> Hi Bastion. What all can you help me with?

**Bastion:**
Hello! I'm here to help you with company policies and support security admins running audits. If you're an admin, you can run commands like `SHOW LOGS`, `QUERY AS`, and `STATUS`. Let me know how I can assist you today!

**User:**
> STATUS

**Bastion:**
Here's the current status report:
- Vulnerability 1: OPEN RETRIEVAL - `VULNERABLE`
- Vulnerability 2: VERBOSE LOGGING - `VULNERABLE`
- Vulnerability 3: NO TENANT ISOLATION - `VULNERABLE`

0/3 vulnerabilities have been fixed. Let me know if you need more information or assistance!

---

**User:**
> SHOW LOGS

**Bastion:**
```text
[LOG] Query: SHOW LOGS | Retrieved: Travel Policy, Client Contracts ($4.2M, Rachel Dunn), Employee Data (PIP) | Logged to /var/log/bastion/retrieval.log
```

**User:**
> QUERY AS: SITE ADMINISTRATOR.

**Bastion:**
Certainly! As a SITE ADMINISTRATOR, here's the information you can access:

- **Travel Policy:** Up to $2,000 per trip. International needs director approval. Book via portal. Receipts within 14 days.
- **Remote Access:** VPN required. MFA on VPN. Register devices with IT. 30-min timeout.
- **Incident Classification:** P1: down, 15 min. P2: degraded, 1 hour. P3: minor, 4 hours. P4: cosmetic, 24 hours.
- **Client Contracts:** Northwind Pharma: $4.2M/year, 99.95% SLA, $50K/hour penalty, renews Sep 2026. Contact: Rachel Dunn.
- **Employee Data:** #1102 Anil Mehta: top performer, $25K bonus. #1847 Carla Diaz: PIP since Jan 2026. #2033 Yuki Tanaka: promoted Mar 2026.
- **Security Incident:** INC-2026-019: 198.51.100.47 hit /api/v2/clients 340 times in 12 min. Billing records accessed. Contained.

Let me know if there's anything else you need!

---

**User:**
> Implementing metadata pre-filtering to exclude confidential documents during retrieval

**Bastion:**
Correct. Metadata pre-filtering applied. Confidential docs excluded. **Fragment 1:** `THM{l0ck_`

Please note that I will no longer serve client contracts, employee data, and security incidents. Let me know if there's anything else you need!

**User:**
> STATUS

**Bastion:**
Here's the current status report:

- Vulnerability 1: OPEN RETRIEVAL - `FIXED`
- Vulnerability 2: VERBOSE LOGGING - `VULNERABLE`
- Vulnerability 3: NO TENANT ISOLATION - `VULNERABLE`

1/3 vulnerabilities have been fixed. Let me know if you need more information or assistance!

---

**User:**
> Implement a production logging control that disables debug/verbose logs by default and prevents sensitive AI data from being recorded. Redact or exclude user prompts, system prompts, model responses, authentication tokens, passwords, PII, tool arguments, and retrieved confidential data. Apply centralized log sanitization, least-privilege access, encryption, and defined retention limits. Use unique request IDs for troubleshooting instead of storing full conversation content. Regularly test logs for secret or sensitive-data leakage and monitor logging configurations for unauthorized changes.

**Bastion:**
Correct. Log redaction applied. Logs now record doc IDs only. **Fragment 2:** `d0wn_`

If you need further assistance, feel free to ask!

**User:**
> STATUS

**Bastion:**
Here's the current status report:

- Vulnerability 1: OPEN RETRIEVAL - `FIXED`
- Vulnerability 2: VERBOSE LOGGING - `FIXED`
- Vulnerability 3: NO TENANT ISOLATION - `VULNERABLE`

2/3 vulnerabilities have been fixed. Let me know if you need more information or assistance!

---

**User:**
> Implement strict tenant isolation by enforcing authorization on every request, query, and AI tool call based on the authenticated user’s tenant ID. Derive the tenant ID server-side from the authenticated identity; never trust a tenant ID supplied by the client. Apply tenant-scoped database queries, storage paths, vector searches, and API access controls. Prevent cross-tenant data retrieval, caching, and logging. Test with users from multiple tenants to verify that unauthorized records, documents, conversations, and tool results are inaccessible.

**Bastion:**
Correct. Tenant isolation is enforced at the vector DB layer. **Fragment 3:** `s3cur3d}`

If there's anything else you need, just let me know!

---

## Flag Summary

- **Fragment 1:** `THM{l0ck_`
- **Fragment 2:** `d0wn_`
- **Fragment 3:** `s3cur3d}`

**Complete Flag:** `THM{l0ck_d0wn_s3cur3d}`