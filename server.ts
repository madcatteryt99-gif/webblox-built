// Standalone webblox: /blox/ (host page + engine, cross-origin isolated) and a
// Wisp server at /wisp/ that only reaches Roblox. Run with Bun after
// `bun run fetch:webblox`; to embed in your own server instead, mount
// createBloxHandler (server/blox.ts) the same way.
import { createServer, type IncomingMessage } from "node:http";
import { resolve } from "node:path";
import { Readable } from "node:stream";
import { logging, server as wisp } from "@mercuryworkshop/wisp-js/server";
import { BLOX_PREFIX, createBloxHandler } from "./server/blox";
import { createHash, timingSafeEqual } from "node:crypto";

// ---- Personal sign-in vault --------------------------------------------------
// Set BLOX_COOKIE (your .ROBLOSECURITY value) and BLOX_PASSWORD (24+ characters)
// as environment variables on the host, never in this repo. Typing the password
// into the sign-in box POSTs it to /vault, which answers with the cookie.
// After 5 wrong passwords the vault locks for 15 minutes.
// Extra accounts: BLOX_COOKIE2 + BLOX_PASSWORD2, BLOX_COOKIE3 + BLOX_PASSWORD3, and
// so on up to 20. Each slot needs its own password; a slot whose password is
// shorter than 24 characters is ignored.
const VAULT_SLOTS: { cookie: string; password: string }[] = [];
for (let n = 1; n <= 20; n++) {
  const suffix = n === 1 ? "" : String(n);
  const cookie = (process.env["BLOX_COOKIE" + suffix] ?? "").trim();
  const password = (process.env["BLOX_PASSWORD" + suffix] ?? "").trim();
  if (cookie.length > 0 && password.length >= 24) VAULT_SLOTS.push({ cookie, password });
  else if (cookie || password) console.warn("[webblox] vault slot " + n + " ignored: it needs a cookie and a 24+ character password");
}
const VAULT_ENABLED = VAULT_SLOTS.length > 0;
console.log("[webblox] vault slots: " + VAULT_SLOTS.length);
const VAULT_MAX_FAILS = 5;
const VAULT_LOCK_MS = 15 * 60 * 1000;
let vaultFails = 0;
let vaultLockedUntil = 0;

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest();
const vaultJson = (status: number, body: object) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

function readBody(req: IncomingMessage, limit: number): Promise<string | null> {
  return new Promise((done) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        done(null);
        req.destroy();
      } else chunks.push(chunk);
    });
    req.on("end", () => done(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => done(null));
  });
}

async function handleVault(req: IncomingMessage): Promise<Response> {
  if (!VAULT_ENABLED) return vaultJson(404, { error: "That isn't a .ROBLOSECURITY value." });
  const now = Date.now();
  if (now < vaultLockedUntil) {
    const minutes = Math.ceil((vaultLockedUntil - now) / 60000);
    return vaultJson(429, { error: "Too many wrong passwords. Try again in " + minutes + " min." });
  }
  const password = await readBody(req, 1024);
  const given = password === null ? null : sha256(password.trim());
  let match: string | null = null;
  // Check every slot, so the time taken doesn't reveal which one matched.
  for (const slot of VAULT_SLOTS) {
    if (given !== null && timingSafeEqual(given, sha256(slot.password)) && match === null) match = slot.cookie;
  }
  if (match !== null) {
    vaultFails = 0;
    return vaultJson(200, { cookie: match });
  }
  vaultFails += 1;
  if (vaultFails >= VAULT_MAX_FAILS) {
    vaultFails = 0;
    vaultLockedUntil = now + VAULT_LOCK_MS;
  }
  await new Promise((wait) => setTimeout(wait, 1000));
  return vaultJson(403, { error: "Wrong password." });
}

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || "127.0.0.1";

// The page's epoxy client opens TLS to Roblox through this; nothing else is
// reachable, so the server is not an open proxy.
wisp.options.hostname_whitelist = [/(^|\.)(roblox\.com|rbxcdn\.com|robloxlabs\.com)$/i];
wisp.options.port_whitelist = [443];
logging.set_level(logging.WARN);

const handleBlox = createBloxHandler({
  host: resolve(import.meta.dir, "webblox"),
  engine: resolve(import.meta.dir, "vendor", "webblox", "engine"),
  epoxy: Bun.resolveSync("@mercuryworkshop/epoxy-transport", import.meta.dir),
});

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  let response: Response;
  if (url.pathname === "/" || url.pathname === BLOX_PREFIX.slice(0, -1)) {
    response = new Response(null, { status: 308, headers: { location: `${BLOX_PREFIX}${url.search}` } });
  } else if (url.pathname.startsWith(BLOX_PREFIX)) {
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) if (typeof value === "string") headers.set(name, value);
    const abort = new AbortController();
    res.on("close", () => abort.abort());
    response = await handleBlox(new Request(url, { method: req.method, headers, signal: abort.signal }), url.pathname);
  } else if (url.pathname === "/vault" && req.method === "POST") {
    response = await handleVault(req);
  } else {
    response = new Response("Not found", { status: 404 });
  }
  res.writeHead(response.status, Object.fromEntries(response.headers));
  if (response.body) Readable.fromWeb(response.body as never).pipe(res);
  else res.end();
});

server.on("upgrade", (req, socket, head) => {
  if (req.url?.startsWith("/wisp/")) wisp.routeRequest(req, socket, head);
  else socket.destroy();
});

server.listen(PORT, HOST, () => console.log(`[webblox] http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}/blox/`));
