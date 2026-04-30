# Mitigation and response for: T1110 - Brute Force
**Internal SOC Runbook: Windows Active Directory Brute Force**

If the SENTINEL system detects a Brute Force attack (T1110), follow these immediate steps:
1. Lock the affected user account(s) immediately via Active Directory Users and Computers (ADUC).
2. Check the source IP address. If it is internal, isolate the host using CrowdStrike Falcon. If it is external, block the IP on the Palo Alto perimeter firewall.
3. Force a password reset for the targeted users. 
4. Review Azure AD sign-in logs for any successful authentications originating from the malicious IP.
5. Escalate the ticket to the Tier 2 Incident Response team with the tag [T1110-CONFIRMED].
