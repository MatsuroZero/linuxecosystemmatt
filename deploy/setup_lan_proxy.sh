#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this script as your normal desktop user, not with sudo."
    exit 1
fi

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${USER}"
USER_HOME="$(getent passwd "${RUN_USER}" | cut -d: -f6)"
DASHBOARD_APP="${DASHBOARD_APP:-${USER_HOME}/Projects/system-dashboard/app.py}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python}"
SERVICE="${DASHBOARD_SERVICE:-system-dashboard.service}"

if [[ ! -f "${DASHBOARD_APP}" ]]; then
    echo "Dashboard source not found: ${DASHBOARD_APP}"
    echo "Set DASHBOARD_APP to the existing System Dashboard app.py path."
    exit 1
fi
if [[ ! -w "${DASHBOARD_APP}" ]]; then
    echo "Dashboard source is not writable by ${RUN_USER}: ${DASHBOARD_APP}"
    exit 1
fi
if ! command -v sudo >/dev/null || ! command -v ip >/dev/null; then
    echo "This setup requires sudo and iproute2."
    exit 1
fi
if ! sudo systemctl cat "${SERVICE}" >/dev/null 2>&1; then
    echo "Systemd service not found: ${SERVICE}"
    exit 1
fi

ROUTE="$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true)"
IFACE="$(awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' <<< "${ROUTE}")"
LAN_IP="${NEXUSONE_LAN_IP:-}"
if [[ -z "${LAN_IP}" && -n "${IFACE}" ]]; then
    LAN_IP="$(ip -o -4 addr show dev "${IFACE}" scope global | awk 'NR==1 {sub(/\/.*/, "", $4); print $4}')"
fi
if [[ -z "${LAN_IP}" ]]; then
    echo "Could not determine a LAN IPv4 address. Set NEXUSONE_LAN_IP manually."
    exit 1
fi
LAN_CIDR="${NEXUSONE_LAN_CIDR:-}"
if [[ -z "${LAN_CIDR}" && -n "${IFACE}" ]]; then
    LAN_CIDR="$(ip -o -4 addr show dev "${IFACE}" scope global | awk 'NR==1 {print $4}')"
fi
if [[ -z "${LAN_CIDR}" ]]; then
    echo "Could not determine the LAN subnet. Set NEXUSONE_LAN_CIDR manually."
    exit 1
fi

echo "Checking the dashboard Python environment..."
PYTHONPATH="${REPO_DIR}" "${PYTHON_BIN}" -c 'import flask, nexusone'
if ! grep -q "install_nexusone_gateway" "${DASHBOARD_APP}"; then
    PYTHONPATH="${REPO_DIR}" "${PYTHON_BIN}" \
        "${REPO_DIR}/deploy/integrate_legacy_dashboard.py" \
        --dashboard-app "${DASHBOARD_APP}"
else
    echo "NexusOne gateway is already present in the dashboard source."
fi
PYTHONPATH="${REPO_DIR}" "${PYTHON_BIN}" -m py_compile "${DASHBOARD_APP}"

if ! command -v caddy >/dev/null; then
    echo "Installing Caddy..."
    sudo pacman -S --needed --noconfirm caddy
fi

sudo install -d -m 0755 /etc/caddy/conf.d
sudo install -d -m 0755 /etc/systemd/system/caddy.service.d
sudo install -d -m 0755 "/etc/systemd/system/${SERVICE}.d"

printf 'NEXUSONE_HOST=%s\n' "${LAN_IP}" | sudo tee /etc/caddy/nexusone.env >/dev/null
sudo chmod 0644 /etc/caddy/nexusone.env

if [[ ! -f /etc/caddy/Caddyfile ]]; then
    printf 'import /etc/caddy/conf.d/*.caddy\n' | sudo tee /etc/caddy/Caddyfile >/dev/null
elif ! sudo grep -Fq 'import /etc/caddy/conf.d/*.caddy' /etc/caddy/Caddyfile; then
    printf '\nimport /etc/caddy/conf.d/*.caddy\n' | sudo tee -a /etc/caddy/Caddyfile >/dev/null
fi

sudo tee /etc/caddy/conf.d/nexusone.caddy >/dev/null <<'CADDY'
https://{$NEXUSONE_HOST}:8443 {
    tls internal
    encode zstd gzip
    reverse_proxy 127.0.0.1:7171 {
        header_up X-Forwarded-Proto {scheme}
    }
}
CADDY

sudo tee /etc/systemd/system/caddy.service.d/nexusone.conf >/dev/null <<'SYSTEMD'
[Service]
EnvironmentFile=/etc/caddy/nexusone.env
SYSTEMD

sudo tee "/etc/systemd/system/${SERVICE}.d/nexusone.conf" >/dev/null <<SYSTEMD
[Service]
Environment=PYTHONPATH=${REPO_DIR}
Environment=NEXUSONE_ALLOW_LAN=1
SYSTEMD

if command -v ufw >/dev/null && sudo ufw status | grep -q 'Status: active'; then
    if ! sudo ufw status | grep -E '7171/tcp.*DENY' >/dev/null; then
        sudo ufw insert 1 deny 7171/tcp
    fi
    if ! sudo ufw status | grep -F "${LAN_CIDR}" | grep -F '8443/tcp' >/dev/null; then
        sudo ufw insert 1 allow from "${LAN_CIDR}" to any port 8443 proto tcp
    fi
    if ! sudo ufw status | grep -E '8443/tcp.*DENY' >/dev/null; then
        sudo ufw insert 2 deny 8443/tcp
    fi
else
    echo "WARNING: UFW is not active. Restrict TCP 7171 to the PC and TCP 8443 to ${LAN_CIDR} in your firewall."
fi

echo "Validating Caddy configuration..."
sudo env NEXUSONE_HOST="${LAN_IP}" caddy validate \
    --config /etc/caddy/Caddyfile --adapter caddyfile

sudo systemctl daemon-reload
sudo systemctl enable --now caddy
sudo systemctl restart caddy
sudo systemctl restart "${SERVICE}"

URL="https://${LAN_IP}:8443/"
CA_SOURCE="$(sudo find /var/lib/caddy -type f -path '*/pki/authorities/local/root.crt' -print -quit 2>/dev/null || true)"
CA_DEST="${USER_HOME}/Downloads/nexusone-local-ca.crt"
if [[ -n "${CA_SOURCE}" ]]; then
    mkdir -p "${USER_HOME}/Downloads"
    sudo install -m 0644 "${CA_SOURCE}" "${CA_DEST}"
    sudo chown "${RUN_USER}:$(id -gn "${RUN_USER}")" "${CA_DEST}"
else
    CA_DEST="not found yet; inspect Caddy's local PKI storage under /var/lib/caddy"
fi

echo
echo "NexusOne LAN setup completed."
echo "Open on your PC or phone: ${URL}"
echo "Import this CA certificate on your phone: ${CA_DEST}"
echo "Backend port 7171 is blocked from LAN access; Caddy serves HTTPS on 8443."
