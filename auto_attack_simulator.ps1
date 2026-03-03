# ================================
# Automated AD Attack Simulation
# Runs every 30 seconds
# ================================

$DC = "WIN-2GV8ISLSBIJ"          # <-- Replace with your Domain Controller hostname
$Domain = "PROJECT"   # <-- replace with your actual domain name
$NormalUser = "$Domain\testuser"   # <-- Replace with a domain user
$NormalPass = "Akashsarkar2001#"  # <-- Replace with correct password
$WrongPass = "WrongPassword123"
$AdminUser = "$Domain\Administrator"     # Domain Admin account
$AdminPass = "Admin123#"

function Simulate-BruteForce {
    Write-Host "[*] Simulating failed login burst..."
    for ($i=1; $i -le 8; $i++) {
        net use \\$DC\IPC$ /user:$NormalUser $WrongPass | Out-Null
        Start-Sleep -Milliseconds 300
    }
}

function Simulate-SuccessAfterFail {
    Write-Host "[*] Simulating success after failures..."
    net use \\$DC\IPC$ /user:$NormalUser $NormalPass | Out-Null
}

function Simulate-PrivilegedLogon {
    Write-Host "[*] Simulating privileged admin logon..."
    net use \\$DC\IPC$ /user:$AdminUser $AdminPass | Out-Null
}

function Simulate-PowerShellExecution {
    Write-Host "[*] Simulating suspicious PowerShell execution..."
    powershell -ExecutionPolicy Bypass -Command "Get-Process | Select-Object -First 1" | Out-Null
}

function Simulate-CmdBurst {
    Write-Host "[*] Simulating rapid CMD execution..."
    for ($i=1; $i -le 5; $i++) {
        cmd /c whoami | Out-Null
    }
}

# ================================
# MAIN LOOP
# ================================

while ($true) {

    Simulate-BruteForce
    Start-Sleep -Seconds 2

    Simulate-SuccessAfterFail
    Start-Sleep -Seconds 2

    Simulate-PrivilegedLogon
    Start-Sleep -Seconds 2

    Simulate-PowerShellExecution
    Start-Sleep -Seconds 2

    Simulate-CmdBurst

    Write-Host "[+] Attack simulation cycle completed. Waiting 30 seconds..."
    Start-Sleep -Seconds 30
}
