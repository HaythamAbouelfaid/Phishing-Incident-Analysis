# LCPS Gift Card Phishing Incident Analysis

![Poster](Phishing_Project_Poster.png)

## Overview
This project documents a real-world phishing attempt targeting my LCPS (Loudoun County Public Schools) email account. 
The attacker impersonated a supervisor ("Kevin Lewis") using a fake Outlook address and attempted to initiate a gift card scam via email and SMS. 
The purpose of this project was to analyze the phishing attempt, perform a technical header review, and demonstrate incident response documentation following cybersecurity best practices.

## Objectives
- Identify key phishing indicators from a real email and text message.
- Analyze email headers for SPF, DKIM, and DMARC validation results.
- Document the social engineering techniques used.
- Create a visual infographic to communicate the incident and lessons learned.

## Tools Used
- Microsoft Outlook (Email Source Header)
- MXToolbox (Header Analysis)
- Canva / PowerPoint (Poster Design)
- Python (for redacting and documenting evidence)

## Framework Mapping

- NIST SP 800-61: Detection & Analysis → Containment → Reporting
- MITRE ATT&CK (Enterprise):
    * T1566 Phishing (initial access)
    * T1656 Financial Theft (via gift cards / social engineering)

## Key Findings
- The email originated from a non-LCPS Outlook domain.
- SPF, DKIM, and DMARC checks showed the sender was unauthorized.
- The attacker attempted a Business Email Compromise (BEC) through social engineering.
- Prompt detection and reporting prevented data or financial loss.

## Visual Summary
📄 **File:** Phishing_Project_Poster.pptx  
A 1-slide infographic showcasing the phishing flow, social engineering tactics, and response actions.

## Lessons Learned
- Always verify sender identity before sharing personal information.
- Watch for urgency, confidentiality, and financial requests.
- Report suspicious messages to IT/Security teams immediately.

## Author
**Haytham Abouelfaid**  
IT & Cybersecurity Student | Google IT & Cybersecurity Certified  
Northern Virginia Community College
