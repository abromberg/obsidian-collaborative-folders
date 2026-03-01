# Local Development

## Prerequisites

- Node.js 22+
- `pnpm` 10+
- Obsidian 0.16+ (for plugin testing)

## Quickstart

1. Install dependencies:

```bash
pnpm install
```

2. Set required server env vars:

```bash
export JWT_SECRET="$(openssl rand -hex 32)" # must be at least 32 chars
```

3. Start the server (default `http://localhost:1234`):

```bash
pnpm --filter @obsidian-teams/server dev
```

4. Build the plugin:

```bash
pnpm --filter @obsidian-teams/plugin build
```

5. Install plugin build artifacts into your vault:

```bash
mkdir -p "<your-vault>/.obsidian/plugins/collaborative-folders"
cp apps/plugin/main.js apps/plugin/manifest.json apps/plugin/styles.css "<your-vault>/.obsidian/plugins/collaborative-folders/"
```

6. In Obsidian, enable the plugin. On first launch the onboarding modal will appear:
- Set your display name
- Choose `Self-deployment` as the service mode
- Enter `http://localhost:1234` as the server URL
