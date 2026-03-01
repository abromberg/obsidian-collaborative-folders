FROM node:22-slim AS base
RUN corepack enable pnpm

WORKDIR /app

# Copy workspace config
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json ./

# Copy package files for dependency install
COPY packages/shared/package.json ./packages/shared/
COPY apps/server/package.json ./apps/server/

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source
COPY packages/shared/ ./packages/shared/
COPY apps/server/ ./apps/server/

# Build shared + server
RUN pnpm --filter @obsidian-teams/shared build
RUN pnpm --filter @obsidian-teams/server build

# Runtime
FROM node:22-slim
WORKDIR /app

# Keep workspace layout because pnpm workspace deps are symlinked.
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/packages/shared ./packages/shared
COPY --from=base /app/apps/server ./apps/server

WORKDIR /app/apps/server
EXPOSE 10000

CMD ["node", "dist/index.js"]
