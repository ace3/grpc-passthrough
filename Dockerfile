FROM oven/bun:1 AS base

WORKDIR /app

# Install dependencies separately for better caching
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy source
COPY . .

EXPOSE 3000

CMD ["bun", "run", "index.ts"]
