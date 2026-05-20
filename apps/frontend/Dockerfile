# AzureLens frontend — Next.js production image (Phase 9 demo).
#
# Uses the `output: "standalone"` build mode from next.config.js to produce
# a minimal self-contained server. `NEXT_PUBLIC_API_BASE_URL` is baked at
# BUILD time per Next.js semantics — pass it as a build arg.

# --------------------------------------------------------------------------
# Stage 1: deps
# --------------------------------------------------------------------------
FROM node:20-alpine AS deps
WORKDIR /app

# No lockfile yet (Phase 9 skeleton). When a lockfile lands, switch to
# `npm ci` and copy package-lock.json explicitly for deterministic installs.
COPY package.json ./
RUN npm install --no-audit --no-fund --ignore-scripts

# --------------------------------------------------------------------------
# Stage 2: builder
# --------------------------------------------------------------------------
FROM node:20-alpine AS builder
WORKDIR /app

# Public env vars baked into the Next.js build. Override at build time:
#   docker build --build-arg NEXT_PUBLIC_API_BASE_URL=https://api.example.com .
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL} \
    NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

# --------------------------------------------------------------------------
# Stage 3: runner (minimal)
# --------------------------------------------------------------------------
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

# Non-root user.
RUN addgroup --system --gid 10001 nodejs \
 && adduser  --system --uid 10001 --ingroup nodejs nextjs

# The standalone output bundles a minimal Node server + the needed modules.
# `public/` and `.next/static` are copied separately.
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER 10001

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
  CMD wget --quiet --spider http://127.0.0.1:3000/ || exit 1

# Next.js standalone server listens on $PORT.
CMD ["node", "server.js"]
