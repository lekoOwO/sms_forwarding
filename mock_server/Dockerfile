FROM node:24.14.0-alpine@sha256:7fddd9ddeae8196abf4a3ef2de34e11f7b1a722119f91f28ddf1e99dcafdf114

ENV PORT=3000 \
    WEB_ROOT=/web/build \
    OPENAPI_PATH=/spec/openapi.json

WORKDIR /app
COPY --chown=node:node mock_server/package.json mock_server/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=node:node mock_server/server.mjs ./
COPY --chown=node:node web/src/lib/forward-rules.js /web/src/lib/forward-rules.js

EXPOSE 3000
USER node

CMD ["npm", "start"]
