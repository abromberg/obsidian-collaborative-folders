> [!IMPORTANT]
> This is a READ-ONLY repo for plugin releases. For issues, pull requests, and server code, see the [the sister monorepo](https://github.com/abromberg/obsidian-collaborative-folders). Changes in the monorepo are mirrored here at release time.

# Obsidian Collaborative Folders

[![Obsidian Collaborative Folders](https://github.com/abromberg/obsidian-collaborative-folders/raw/main/apps/server/media/collaborativefolders_header.png)](https://collaborativefolders.com)

Real-time, multiplayer shared folders and notes for [Obsidian](https://obsidian.md/). Deploy it yourself or use our hosted service — and either way, notes are encrypted end-to-end. Everything you love about Google Docs, but in your lovely local Obsidian instance. Fully MIT-licensed. 

**Warning: Beta software.** This project is still in active development and may contain bugs, breaking changes, data leakage, or data-loss risks; use at your own risk and keep backups of important vaults.

After installing the plugin, right click on a folder and select `Share folder...`. Send the invite URL to a friend or teammate and the folder will appear in their vault. You can see each others' cursors in the file and edit collaboratively in realtime. 

As long as Obsidian is open, updates you make will be synced to other people shared on the folder, so feel free to use Claude Code or your favorite AI tools on the shared folders and the changes will propagate automatically.

## Demo

https://github.com/user-attachments/assets/16018201-8fa3-456d-89f8-67fc776045ae

[Open demo video directly](https://collaborativefolders.com/media/collab_demo.mp4)

_This is a community plugin maintained by [Andy Bromberg](https://andybromberg.com) at Experimental LLC. Neither Andy nor Experimental LLC are affiliated with Obsidian._

## Installing Before Obsidian Community Approval

The valiant Obsidian plugin reviewing team is facing an onslaught of submissions. It may be weeks or months until they get to this one and add it to the real directory. Until then, you can install it with a helper plugin called [BRAT](https://tfthacker.com/BRAT).

1. [Install BRAT](https://obsidian.md/plugins?id=brat). Alternatively, in Obsidian, open `Settings` -> `Community plugins` and install `BRAT`. (You'll have to turn on `Community plugins` first if you haven't already)
2. Toggle BRAT "on" in the community plugins list.
3. Open BRAT settings and choose `Add beta plugin`.
4. Enter this repository URL: `https://github.com/abromberg/obsidian-collaborative-folders-plugin` and hit `Add`
5. On first launch the plugin opens an onboarding modal — enter your display name and choose a service mode:
   - **Hosted service** (recommended): enter your email, then verify it with a one-time code in plugin settings and subscribe
   - **Self-deployment**: follow the Server Deployment section below and enter your deployment URL

## (Optional) Server Deployment

See the sister monorepo https://github.com/abromberg/obsidian-collaborative-folders for information on server deployment.

## What This Repo Contains

- Obsidian plugin for sharing folders and the notes within them, with live collaborative editing.
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

See the sister monorepo https://github.com/abromberg/obsidian-collaborative-folders for server-side code.

## Data Flow

See the sister monorepo https://github.com/abromberg/obsidian-collaborative-folders for information on data flows.

## Local Development

See the sister monorepo https://github.com/abromberg/obsidian-collaborative-folders for information on local development.

## Contributing

Contributions are welcome, but should be made in the sister monorepo https://github.com/abromberg/obsidian-collaborative-folders. Changes there are synced to this plugin-only repo regularly.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
