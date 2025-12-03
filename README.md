# OpenSSH Server Installer for dstack

A Docker-based installer for OpenSSH Server on read-only dstack systems.

## Quick Start

### Build the Installer

```bash
chmod +x build.sh
./build.sh $NS/dstack-openssh-installer latest
docker push $NS/dstack-openssh-installer:latest
```

### Install OpenSSH Server

Put one of the instuction below in the prelaunch script of a dstack instance.

**Single command installation with SSH public key:**
```bash
docker run --rm --privileged --pid=host --net=host -v /:/host \
  -e SSH_PUBKEY="ssh-ed25519 AAAA... user@host" \
  $NS/dstack-openssh-installer:latest
```

**Import ssh public keys from GitHub username:**
```bash
docker run --rm --privileged --pid=host --net=host -v /:/host \
  -e SSH_GITHUB_USER="octocat" \
  $NS/dstack-openssh-installer:latest
```

**Custom port:**
```bash
docker run --rm --privileged --pid=host --net=host -v /:/host \
  -e SSH_PORT=2222 \
  -e SSH_PUBKEY="ssh-ed25519 AAAA..." \
  $NS/dstack-openssh-installer:latest
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_PORT` | `22` | SSH listening port |
| `SSH_PUBKEY` | - | SSH public key for root login |
| `SSH_GITHUB_USER` | - | GitHub username to import public keys from |
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | Root login policy (`yes`, `no`, `prohibit-password`) |

## Usage After Installation

### Connect via SSH (through dstack gateway)

dstack TEE applications are accessed through a gateway using TLS tunneling.

**1. Configure SSH client**

Add the following to your `~/.ssh/config`:

```
Host my-tee-app
    ProxyCommand openssl s_client -quiet -connect <app-id>-<port>.<gateway-domain>:443
```

Replace:
- `<app-id>`: Your application ID
- `<port>`: SSH port (default: 22, or your custom port like 2222)
- `<gateway-domain>`: The dstack gateway domain

**Example:**
```
Host my-tee-app
    ProxyCommand openssl s_client -quiet -connect c3c0ed2429a72e11e07c8d5701725968ff234dc0-22.dstack-prod5.phala.network:443
```

**2. Connect**

```bash
ssh root@my-tee-app
```

**macOS Note:** The built-in LibreSSL may cause connection timeouts. Install OpenSSL via Homebrew:
```bash
brew install openssl
```
Then use the full path in ProxyCommand: `/opt/homebrew/opt/openssl/bin/openssl`

