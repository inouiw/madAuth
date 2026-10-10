# Build from the repository root: docker build -f packages/server/Dockerfile -t madauth-server .
FROM node:22-alpine AS build
WORKDIR /repo
COPY package.json package-lock.json ./
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
COPY demo/package.json demo/
COPY site/package.json site/
RUN npm ci --workspace @madauth/server --include-workspace-root=false --ignore-scripts
COPY tsconfig.base.json ./
COPY packages/server packages/server
RUN npm run build --workspace @madauth/server

# The bundle is self-contained, so the runtime image needs no node_modules.
FROM node:22-alpine
WORKDIR /app
COPY --from=build /repo/packages/server/dist/standalone/main.mjs ./main.mjs
# For DATABASE_URL=sqlite:/data/madauth.db: a volume the unprivileged user can write to.
RUN mkdir /data && chown node:node /data
VOLUME /data
USER node
ENV NODE_ENV=production PORT=8787
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${PORT}/health || exit 1
CMD ["node", "main.mjs"]
