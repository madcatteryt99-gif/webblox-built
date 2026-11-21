FROM node:20-slim
RUN npm install -g bun
WORKDIR /app
COPY . .
RUN bun install && bun run fetch:webblox version-f807b21caba84809
ENV HOST=0.0.0.0
EXPOSE 8080
CMD ["bun", "server.ts"]
