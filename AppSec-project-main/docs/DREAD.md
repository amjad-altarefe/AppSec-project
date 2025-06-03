# DREAD Risk Assessment Report

## Application Name: Secure Login Portal
## Team Members: Amjad, Ali, Sarah

---

## Step 1: Identify Potential Threats

Through analysis of the login/registration system and session-based authentication model, the following threats were identified:

- Session Hijacking  
- Credential Stuffing  
- Cross-Site Scripting (XSS)  
- Brute Force Login Attempts  
- Privilege Escalation  

---

## Step 2: Assess Each Threat Using DREAD

Each threat is scored on the following criteria (1 (low risk) - 10 (high risk)):

Damage = (D)
Reproducibility = (R)
Exploitability = (E)
Affected Users = (A)
Discoverability = (D)

| Threat               | (D) | (R) | (E) | (A) | (D) | Total Score | Risk Level |
|----------------------|-----|-----|-----|-----|-----|-------------|------------|
| Session Hijacking    | 7   | 6   | 6   | 7   | 6   | **32**      | High       |
| Credential Stuffing  | 6   | 7   | 7   | 7   | 6   | **33**      | High       |
| XSS via form input   | 5   | 6   | 6   | 5   | 5   | **27**      | Medium     |
| Brute Force Login    | 5   | 5   | 5   | 6   | 6   | **27**      | Medium     |
| Privilege Escalation | 7   | 6   | 5   | 6   | 6   | **30**      | High       |

---

## Step 3: Prioritize Threats

Based on total DREAD scores, threats are prioritized as follows:

1. Credential Stuffing (**33**) – High Priority  
2. Session Hijacking (**32**) – High Priority  
3. Privilege Escalation (**30**) – High Priority  
4. XSS (**27**) – Medium Priority  
5. Brute Force (**27**) – Medium Priority  

---

## Step 4: Develop Mitigation Strategies

| Threat               | Mitigation Strategy                                                                       |
|----------------------|-------------------------------------------------------------------------------------------|
| Session Hijacking    | Use secure, HTTPOnly, SameSite cookies; regenerate session IDs after login                |
| Credential Stuffing  | Rate limiting, strong password policy, CAPTCHA, optional 2FA                              |
| XSS                  | Sanitize all input/output using DOMPurify (frontend) or validator/sanitize-html (backend) |
| Brute Force Login    | Apply account lockout, rate limiting, and CAPTCHA mechanisms                              |
| Privilege Escalation | Server-side role-based access control; never trust client-side roles                      |