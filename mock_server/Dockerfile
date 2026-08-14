FROM node:22-alpine

RUN apk add --no-cache chromium

ENV PORT=3000 \
    WEB_ROOT=/web \
    OPENAPI_PATH=/spec/openapi.json \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY server.mjs ./
COPY test ./test

EXPOSE 3000
USER node

CMD ["npm", "start"]
