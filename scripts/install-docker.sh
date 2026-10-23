#!/usr/bin/env bash
set -euo pipefail

# Install Docker Engine and Docker Compose plugin on Ubuntu/Debian.
# Run with sudo or as root.

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root or with sudo." >&2
   exit 1
fi

# Remove any conflicting distro packages
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    apt-get remove -y "$pkg" 2>/dev/null || true
done

# Install prerequisites
apt-get update
apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update

# Install Docker
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Add the calling user to the docker group if this was run via sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    usermod -aG docker "$SUDO_USER"
    echo "Added $SUDO_USER to the docker group. Log out and back in for this to take effect."
fi

echo "Docker installed successfully."
docker --version
docker compose version
