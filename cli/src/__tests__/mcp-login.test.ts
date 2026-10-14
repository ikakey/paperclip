import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:timers/promises", () => ({ setTimeout: async () => undefined }));
const { credentialPath, loginMcpDevice, mcpApprovalOrigin, mcpScopes } = await import("../client/mcp-auth.js");

const origin = "https://mcp.example";
const approval = "https://approve.tailnet.example";
const resource = origin + "/mcp/paperclip";
const company = "8623a19f-d382-40f3-b169-0a8423b1ccd1";
let home: string;
beforeEach(async () => { home = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-login-")); vi.stubEnv("PAPERCLIP_HOME", home); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); await fs.rm(home, { recursive: true, force: true }); });

/** Minimal in-memory authorization server; `verification` and `authorization` model what a server advertises. */
function server(opts: { verification?: string; authorization?: string; scope?: string } = {}) {
  const calls: { url: string; body?: Record<string, unknown> }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(init.body as string) : undefined; calls.push({ url, body });
    if (url.includes("oauth-protected-resource")) return Response.json({ resource, authorization_servers: [origin] });
    if (url.includes("oauth-authorization-server")) return Response.json({ issuer: origin, token_endpoint: origin + "/mcp/oauth/token",
      device_authorization_endpoint: origin + "/mcp/oauth/device_authorization", registration_endpoint: origin + "/mcp/oauth/register",
      authorization_endpoint: opts.authorization ?? origin + "/mcp/oauth/authorize" });
    if (url.endsWith("/mcp/oauth/register")) return Response.json({ client_id: "device-client" }, { status: 201 });
    if (url.endsWith("/mcp/oauth/device_authorization")) return Response.json({ device_code: "dc", user_code: "ABCD-1234", expires_in: 600, interval: 5,
      verification_uri: (opts.verification ?? origin) + "/mcp-device" });
    if (url.endsWith("/mcp/oauth/token")) return Response.json({ access_token: "access", token_type: "Bearer", expires_in: 900, scope: opts.scope ?? "paperclip:read paperclip:write" });
    if (url === resource) return Response.json({ jsonrpc: "2.0", id: "1", result: { structuredContent: { companyId: company } } });
    throw new Error("unexpected request " + url);
  }));
  return calls;
}
const scopeOf = (calls: { url: string; body?: Record<string, unknown> }[]) => calls.find(call => call.url.endsWith("/device_authorization"))?.body?.scope;

describe("MCP device login", () => {
  it("requests exactly the chosen scopes and accepts the explicitly allowed private approval origin", async () => {
    const calls = server({ verification: approval, authorization: approval + "/mcp/oauth/authorize" }); const notify = vi.fn();
    const result = await loginMcpDevice(resource, company, notify, { scopes: mcpScopes("paperclip:read paperclip:write"), approvalOrigin: approval });
    expect(scopeOf(calls)).toBe("paperclip:read paperclip:write");
    expect(notify).toHaveBeenCalledWith(expect.stringContaining(approval + "/mcp-device?user_code=ABCD-1234"));
    expect(result).toEqual({ resource, companyId: company, scope: "paperclip:read paperclip:write" });
    const saved = JSON.parse(await fs.readFile(credentialPath(resource), "utf8"));
    expect(saved).toMatchObject({ issuer: origin, companyId: company, accessToken: "access" });
    expect(saved.refreshToken).toBeUndefined();
    expect(JSON.stringify(calls.map(call => call.body))).not.toContain("offline_access");
  });
  it("rejects an approval origin the user did not allow, even when the server advertises it", async () => {
    server({ verification: "https://evil.example", authorization: "https://evil.example/mcp/oauth/authorize" });
    await expect(loginMcpDevice(resource, company, vi.fn(), { approvalOrigin: approval })).rejects.toThrow("different approval origin");
    server({ verification: "https://evil.example", authorization: approval + "/mcp/oauth/authorize" });
    await expect(loginMcpDevice(resource, company, vi.fn(), { approvalOrigin: approval })).rejects.toThrow("Could not start device authorization");
    await expect(fs.stat(credentialPath(resource))).rejects.toThrow();
  });
  it("registers nothing when the advertised approval origin is not the allowed one", async () => {
    const calls = server({ authorization: "https://evil.example/mcp/oauth/authorize" });
    await expect(loginMcpDevice(resource, company, vi.fn(), { approvalOrigin: approval })).rejects.toThrow();
    expect(calls.some(call => call.url.endsWith("/register"))).toBe(false);
  });
  it("keeps the same-origin default: a foreign verification link is refused without --approval-origin", async () => {
    server({ verification: approval });
    await expect(loginMcpDevice(resource, company, vi.fn())).rejects.toThrow("Could not start device authorization");
  });
  it("keeps the previous default of the full public scope catalog when no scope is chosen", async () => {
    const calls = server();
    await loginMcpDevice(resource, company, vi.fn());
    expect(scopeOf(calls)).toBe("paperclip:read paperclip:write paperclip:configure offline_access");
  });
});

describe("MCP login option validation", () => {
  it("accepts only known scopes that include read, deduplicated and without adding offline_access", () => {
    expect(mcpScopes("paperclip:read paperclip:write")).toEqual(["paperclip:read", "paperclip:write"]);
    expect(mcpScopes("paperclip:read,paperclip:write,paperclip:read")).toEqual(["paperclip:read", "paperclip:write"]);
    expect(mcpScopes("paperclip:read")).not.toContain("offline_access");
    for (const bad of ["", "paperclip:write", "paperclip:read admin", "paperclip:read paperclip:agent"]) expect(() => mcpScopes(bad)).toThrow("--scope");
  });
  it("accepts only an HTTPS origin (or loopback HTTP) for the approval page", () => {
    expect(mcpApprovalOrigin(approval + "/")).toBe(approval);
    expect(mcpApprovalOrigin("http://127.0.0.1:3200")).toBe("http://127.0.0.1:3200");
    for (const bad of ["http://approve.example", approval + "/mcp-device", approval + "?x=1", "https://u:p@approve.example", "not a url"]) expect(() => mcpApprovalOrigin(bad)).toThrow();
  });
});
