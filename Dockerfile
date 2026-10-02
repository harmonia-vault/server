FROM node:24.16.0-bookworm-slim AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global pnpm@11.5.2 && pnpm install --frozen-lockfile
COPY tsconfig*.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod
FROM node:24.16.0-bookworm-slim
ENV NODE_ENV=production HARMONIA_DATABASE=/data/harmonia.sqlite
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir /data && chown node:node /data && chmod 700 /data
USER node
VOLUME ["/data"]
# Loopback binding is deliberate. Use a TLS sidecar sharing this network namespace.
CMD ["node", "dist/node.js"]
