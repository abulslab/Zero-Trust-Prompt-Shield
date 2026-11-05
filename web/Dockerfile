# Build from the repository root: docker build -f web/Dockerfile --build-arg NEXT_PUBLIC_API_URL=http://localhost:5380 .
FROM node:22-alpine AS build
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# The browser calls the API directly, so its public URL is baked into the client bundle at build time.
ARG NEXT_PUBLIC_API_URL=http://localhost:5380
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine
WORKDIR /web
ENV NODE_ENV=production PORT=3200 HOSTNAME=0.0.0.0 NEXT_TELEMETRY_DISABLED=1
COPY --from=build /web/.next/standalone ./
COPY --from=build /web/.next/static ./.next/static
COPY --from=build /web/public ./public
EXPOSE 3200
USER node
CMD ["node", "server.js"]
