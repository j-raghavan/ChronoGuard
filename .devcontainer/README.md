# ChronoGuard Codespaces Configuration

This directory contains the configuration for running ChronoGuard in GitHub Codespaces.

## Files

- `devcontainer.json` - Codespaces container configuration
- `setup-demo.sh` - Auto-setup script that runs on container creation

## What Happens When You Launch

1. **Container Creation** (~30 seconds)
   - GitHub builds the dev container
   - Installs Docker, Python 3.11, Node.js
   - Sets up VS Code extensions

2. **Auto-Setup** (~60-90 seconds)
   - `setup-demo.sh` runs automatically
   - Installs Playwright and dependencies
   - Generates secure secrets
   - Starts all 6 ChronoGuard services
   - Seeds demo data
   - Displays welcome message

3. **Ready to Use** ✅
   - Dashboard auto-opens on port 3000
   - API docs available on port 8000
   - Demo scripts ready to run

## Port Forwarding

Codespaces automatically forwards these ports:

| Port | Service | Auto-Open |
|------|---------|-----------|
| 3000 | Dashboard | ✅ Yes |
| 8000 | API & Docs | Notify |
| 8080 | Envoy Proxy | Silent |
| 8181 | OPA Engine | Silent |
| 9901 | Envoy Admin | Silent |

## Manual Setup (If Needed)

If auto-setup fails, run manually:

```bash
bash .devcontainer/setup-demo.sh
```

## Troubleshooting

### Services not starting
```bash
docker compose -f docker-compose.demo.yml down
docker compose -f docker-compose.demo.yml up -d
```

### Port forwarding not working
- Check Ports tab in VS Code
- Click on port to open in browser
- Ensure ports are set to "Public" if needed

### Demo scripts failing
```bash
# Reinstall dependencies
pip install playwright requests rich
playwright install chromium
```

## Development

To make changes to the devcontainer:

1. Edit `devcontainer.json` or `setup-demo.sh`
2. Rebuild container: Command Palette → "Rebuild Container"
3. Test changes

## More Info

- [Codespaces Docs](https://docs.github.com/en/codespaces)
- [Devcontainer Spec](https://containers.dev/)
- [ChronoGuard Docs](../docs/)
