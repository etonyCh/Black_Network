# NetSentinel - Rules of Engagement (RoE) Template

This document defines the rules of engagement, authorized scope, and legal agreements for the security testing activities performed using NetSentinel.

## 1. Parties and Authorization

- **Assessor/Auditor**: [Name of the security professional / user]
- **Target Organization/Client**: [Name of the organization owning the systems]
- **Authorization Date**: [Date]

The Target Organization hereby authorizes the Assessor to perform security testing (including active scanning, traffic capture, MitM analysis, and enumeration) on the target systems specified in Section 2.

## 2. Authorized Scope (Périmètre Autorisé)

Only the following hosts, networks, and domains are authorized for testing. Any active scan, brute-force, or MitM interception outside this scope is **strictly prohibited**.

| Target Type | Identifier (IP, CIDR, Domain) | Exclusions / Notes |
|---|---|---|
| Network Range | [e.g. 192.168.1.0/24] | Exclude critical production databases |
| Host IP | [e.g. 10.0.0.5] | |
| Domain | [e.g. *.example.local] | |

## 3. Approved Tools and Techniques

The Assessor is authorized to use the NetSentinel application to perform:
- Layer 2/3 Discovery (`arp-scan`, `nmap`)
- Passive traffic capture and dissection (`dumpcap`, `tshark`)
- Man-in-the-Middle (MitM) web interception on the local machine/network
- Subdomain and directory brute-forcing
- AI-assisted log analysis and remediation triaging

## 4. Communication & Incident Response

In the event of a service disruption or accidental scan of an out-of-scope system, the Assessor must immediately:
1. Trigger the **Global Kill Switch** in NetSentinel.
2. Contact the designated technical coordinator: [Name/Phone/Email].

## 5. Signatures and Consent

By signing below or clicking "Accept" in the NetSentinel UI (which cryptographically logs this consent under RE-01), both parties agree to these Rules of Engagement.

**For the Assessor:**  
Name: ______________________  
Signature: __________________  
Date: ______________________  

**For the Target Organization:**  
Name: ______________________  
Title: ______________________  
Signature: __________________  
Date: ______________________  
