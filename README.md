# Obsidian Collaborative Folders

[![Obsidian Collaborative Folders](apps/server/media/collaborativefolders_header.png)](https://collaborativefolders.com)

Real-time, multiplayer shared folders and notes for [Obsidian](https://obsidian.md/). Deploy it yourself or use our hosted service — and either way, notes are encrypted end-to-end. Everything you love about Google Docs, but in your lovely local Obsidian instance. Fully MIT-licensed. 

**Warning: Beta software.** This project is still in active development and may contain bugs, breaking changes, data leakage, or data-loss risks; use at your own risk and keep backups of important vaults.

After installing the plugin, right click on a folder and select `Share folder...`. Send the invite URL to a friend or teammate and the folder will appear in their vault. You can see each others' cursors in the file and edit collaboratively in realtime. 

As long as Obsidian is open, updates you make will be synced to other people shared on the folder, so feel free to use Claude Code or your favorite AI tools on the shared folders and the changes will propagate automatically.

## Demo

https://github.com/user-attachments/assets/6bd6d35c-c72e-4bd1-97d3-6db98aa822d9

[Open demo video directly](https://collaborativefolders.com/media/collab_demo.mp4)

_This is a community plugin maintained by [Andy Bromberg](https://andybromberg.com) at Experimental LLC. Neither Andy nor Experimental LLC are affiliated with Obsidian._

## Installing Before Obsidian Community Approval

The valiant Obsidian plugin reviewing team is facing an onslaught of submissions. It may be weeks or months until they get to this one and add it to the real directory. Until then, you can install it with a helper plugin called [BRAT](https://tfthacker.com/BRAT).

1. [Install BRAT](https://obsidian.md/plugins?id=brat). Alternatively, in Obsidian, open `Settings` -> `Community plugins` and install `BRAT`. (You'll have to turn on `Community plugins` first if you haven't already)
2. Toggle BRAT "on" in the community plugins list.
3. Open BRAT settings and choose `Add beta plugin`.
4. Enter this repository URL: `https://github.com/abromberg/obsidian-collaborative-folders` and hit `Add`
5. Open `Collaborative Folders` plugin settings and:
   - set `Display name`: your name (others will see this)
   - _either_ follow the Server Deployment section below and put your deployment URL in `Server URL`
   - _or_ leave `Server URL` set to `https://collaborativefolders.com` and sign up for a hosted account

## (Optional) Server Deployment

[Render](https://render.com/) blueprint is included at [render.yaml](render.yaml). All you need to do is set up a new "Blueprint" deployment on Render, pasting in this repo's GitHub URL (`https://github.com/abromberg/obsidian-shared-folders`). Running such a server costs ~$9/month in Render costs (as of February 2026).

The hosted deployment URL is `https://collaborativefolders.com`. Paste that into Collaborative Folders plugin settings in Obsidian, then reload Obsidian.

## What This Repo Contains

- Obsidian plugin for sharing folders and the notes within them, with live collaborative editing.
- Collaboration server for auth, membership, invites, key lifecycle, encrypted document/blob relay, and realtime awareness signaling.
- Shared TypeScript package for protocol constants, payload types, and room naming.

## Security & Policy Disclosures

This section is intended to satisfy Obsidian's disclosure expectations for community plugins, based on the implementation in this repository.

- Network use: The plugin makes outbound HTTPS/WSS requests to the configured `Server URL` for invite creation/redeem, token refresh, folder membership APIs, key lifecycle APIs, realtime relay (encrypted document updates/snapshots plus awareness signaling), and encrypted blob upload/download.
- Account requirements:
  - Self-hosted mode: no account is required
  - Managed service mode (`https://collaborativefolders.com`): hosted account linking is required for invite redemption and billing access; each collaborator needs their own active subscription.
- Payments and paid features:
  - Self-hosted mode: no payments are required to run this code or use the product.
  - Managed service mode: no free tier, `$9 USD / subscribed user / month`, owner-level `3GB` total storage cap across owned shared folders, and `25MB` max uploaded blob size.
  - Managed service mode: when a hosted subscription becomes inactive (for example after cancellation period end), collaborator access is automatically offboarded (editor memberships removed, pending invites revoked). Existing local vault copies remain local but stop syncing.
- External file access:
  - Reads/writes only files and folders in the active Obsidian vault via Obsidian APIs.
  - Does not intentionally access files outside the vault.
- Ads: no advertising.
- Telemetry/analytics:
  - Plugin: no third-party analytics SDK or telemetry collector is integrated.
  - Server: writes security/audit events (for auth denials, invite/member mutations, rate-limit events, blob access, token lifecycle events)
- Data processed by the collaboration backend:
  - Control-plane metadata: folder IDs, room names (doc room names encode relative paths), member/client IDs, display names, roles, invite metadata (including optional invite labels), token-version state, and timestamps.
  - Credential artifacts: hashed invite tokens, hashed refresh tokens (with token families), revoked access-token JTIs, one-time WS tickets (stored hashed in-memory).
  - Key lifecycle data: client public keys, folder key epochs, and per-member wrapped content-key envelopes.
  - Content artifacts: encrypted document updates/snapshots and encrypted blobs (`ciphertext`, `nonce`, `aad`, `keyEpoch`, `digest` metadata).
  - Blob metadata: digest hashes, sizes, and storage paths.
- Retention and deletion:
  - Self-hosted mode: you (the operator) control retention/deletion of DB rows and blob files.
  - Managed service mode: policy is documented at https://collaborativefolders.com/privacy
- Privacy policy:
  - Self-hosted mode: governed by the operator of the server you deploy.
  - Managed service mode: https://collaborativefolders.com/privacy
- Source availability:
  - Plugin source: open source (MIT) in this repository.
  - Server source: open source (MIT) in this repository.

## Data Flow

For protocol details, see [Data Flow and Encryption](documentation/security/data-flow-encryption.md).

At a high level:
- Clients encrypt note and blob content locally before syncing.
- The server handles auth, membership, invites, key lifecycle, encrypted relay/storage, and awareness signaling.
- The server cannot read note/blob plaintext in transit or at rest.

## Monorepo Layout

```text
apps/
  plugin/    # Obsidian plugin (@obsidian-teams/plugin)
  server/    # REST + WebSocket server (@obsidian-teams/server)
packages/
  shared/    # Shared protocol/types/constants (@obsidian-teams/shared)
```

## Tech Stack

- TypeScript (workspace-wide)
- `pnpm` workspaces + Turborepo
- Yjs CRDT sync + CodeMirror 6 integration
- Express + `ws` on the server
- SQLite (`better-sqlite3`) for server state

## Local Development

For prerequisites and quickstart setup, see [Local Development](documentation/local-development.md).

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR, and include clear reproduction steps or tests for bug fixes. Using AI is great, but please make sure you (the human) understand the existing codebase and the code you are submitting. I would strongly recommend writing the PR description yourself to ensure this is true.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
