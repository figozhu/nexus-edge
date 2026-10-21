import { describe, expect, test } from "bun:test";
import { EventEmitter, getEventListeners } from "node:events";
import * as https from "node:https";
import type * as http from "node:http";
import type * as os from "node:os";
import { createHttpsAddressTransport, detectPublicAddresses, isPublicIp, listLocalAddresses } from "../src/address.ts";
import type { AddressHttpsRequest, AddressTransport, AddressTransportRequest } from "../src/address.ts";

const ipify4 = "https://api.ipify.org/?format=json", aws4 = "https://checkip.amazonaws.com/";
const ipify6 = "https://api6.ipify.org/?format=json", cloudflare6 = "https://www.cloudflare.com/cdn-cgi/trace";

describe("strict public-address classification", () => {
  test("accepts global IPv4 and exact globally reachable special assignments", () => {
    for (const value of ["1.1.1.1", "8.8.8.8", "45.32.22.10", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1", "192.0.0.9", "192.0.0.10", "192.31.196.1", "223.255.255.254"]) expect(isPublicIp(value)).toBe(true);
  });
  test("rejects local, shared, documentation, benchmark, multicast and reserved IPv4", () => {
    for (const value of ["0.0.0.0", "0.9.8.7", "10.255.255.254", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.99.8.7", "169.254.1.2", "172.16.0.1", "172.31.255.254", "192.0.0.8", "192.0.0.170", "192.0.2.1", "192.88.99.2", "192.168.1.10", "198.18.0.1", "198.19.255.254", "198.51.100.10", "203.0.113.10", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255"]) expect(isPublicIp(value)).toBe(false);
  });
  test("accepts ordinary global IPv6 including canonical equivalents", () => {
    for (const value of ["2606:4700:4700::1111", "2001:4860:4860::8888", "2a01:4f9:3b:1234::2", "2001:19f0:6001::1", "2606:4700:4700:0:0:0:0:1111", "2A01:4F9:3B:1234::2", "2001:1::1", "2001:3::abcd"]) expect(isPublicIp(value)).toBe(true);
  });
  test("rejects IPv6 local, scoped, mapped, transition, identifier and documentation ranges", () => {
    for (const value of ["::", "::1", "::ffff:8.8.8.8", "::ffff:192.168.0.1", "64:ff9b::808:808", "100::1", "100:0:0:1::1", "2001::1", "2001:2::1", "2001:10::1", "2001:20::1", "2001:30::1", "2001:db8::1", "2002:0808:0808::1", "3fff::1", "3fff:fff::1", "5f00::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "2606:4700::1%eth0", "fe80::1%3"]) expect(isPublicIp(value)).toBe(false);
  });
  test("rejects non-literals, alternate IPv4 encodings, extra data and URL syntax", () => {
    for (const value of ["", "localhost", "api.ipify.org", "8.8.8", "008.8.8.8", "0x08080808", "134744072", "8.8.8.8:443", "8.8.8.8/32", "[2606:4700::1]", "https://8.8.8.8", " 8.8.8.8", "8.8.8.8\n", "8.8.8.8\n1.1.1.1", "8.8.8.8\u0000"]) expect(isPublicIp(value)).toBe(false);
  });
});

interface Plan { body?: string; delay?: number; fail?: boolean; hang?: boolean }
function probeMock(plan: Record<string, Plan>) {
  const calls: { request: AddressTransportRequest; aborted: boolean; finished: boolean }[] = [];
  const transport: AddressTransport = request => new Promise((resolve, reject) => {
    const call = { request, aborted: false, finished: false }; calls.push(call);
    const item = plan[request.url] ?? { fail: true };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: Error) => {
      if (call.finished) return;
      call.finished = true; if (timer) clearTimeout(timer); request.signal.removeEventListener("abort", abort);
      if (error) reject(error); else resolve(item.body ?? "");
    };
    const abort = () => { call.aborted = true; finish(new Error("mock cancellation")); };
    request.signal.addEventListener("abort", abort, { once: true });
    if (request.signal.aborted) abort();
    else if (!item.hang) timer = setTimeout(() => finish(item.fail ? new Error("mock network failure") : undefined), item.delay ?? 0);
  });
  return { calls, transport };
}

describe("public address discovery with no network requests", () => {
  test("IPv4 wins even when IPv6 returns first; both observations keep their sources", async () => {
    const mock = probeMock({ [ipify4]: { body: '{"ip":"45.32.22.10"}', delay: 10 }, [aws4]: { hang: true },
      [ipify6]: { body: '{"ip":"2606:4700:4700:0:0:0:0:1111"}' }, [cloudflare6]: { hang: true } });
    const result = await detectPublicAddresses({}, mock.transport);
    expect(result.preferredAddress).toBe("45.32.22.10"); expect(result.ipv4).toBe("45.32.22.10"); expect(result.ipv6).toBe("2606:4700:4700::1111");
    expect(result.source).toEqual({ ipv4: ipify4, ipv6: ipify6 }); expect(result.cancelled).toBe(false);
    expect(result.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(result.warnings.join(" ")).toContain("出口公网 IP"); expect(result.warnings.join(" ")).toContain("NAT");
    expect(mock.calls.every(call => call.finished)).toBe(true);
  });
  test("IPv4 success cancels other probes immediately without declaring IPv6 unavailable", async () => {
    const mock = probeMock({ [aws4]: { body: "8.8.4.4\n" }, [ipify4]: { hang: true }, [ipify6]: { hang: true }, [cloudflare6]: { hang: true } });
    const result = await detectPublicAddresses({}, mock.transport);
    expect(result.preferredAddress).toBe("8.8.4.4"); expect(result.ipv6).toBeNull(); expect(result.source.ipv4).toBe(aws4);
    expect(mock.calls.filter(call => call.aborted)).toHaveLength(3); expect(mock.calls.every(call => call.finished)).toBe(true);
    expect(result.warnings.join(" ")).not.toContain("不支持 IPv6");
  });
  test("invalid IPv4 provider data falls back to another provider", async () => {
    const mock = probeMock({ [ipify4]: { body: '{"ip":"10.0.0.1"}' }, [aws4]: { body: "1.1.1.1\n", delay: 5 } });
    const result = await detectPublicAddresses({}, mock.transport);
    expect(result.ipv4).toBe("1.1.1.1"); expect(result.source.ipv4).toBe(aws4);
  });
  test("IPv6 fallback parses exactly one trace IP and reports an observed system WARP", async () => {
    const mock = probeMock({ [cloudflare6]: { body: "fl=123\nip=2606:4700:110:8123::2\nwarp=on\ncolo=SJC\n" } });
    const result = await detectPublicAddresses({}, mock.transport);
    expect(result.preferredAddress).toBe("2606:4700:110:8123::2"); expect(result.ipv4).toBeNull();
    expect(result.source.ipv6).toBe(cloudflare6); expect(result.warnings.join(" ")).toContain("仅识别到 IPv6");
    expect(result.warnings.join(" ")).toContain("WARP 正在生效");
  });
  test("wrong families, duplicate trace IPs and arbitrary HTML do not become addresses", async () => {
    const mock = probeMock({ [ipify4]: { body: '{"ip":"2606:4700::1"}' }, [aws4]: { body: "<html>8.8.8.8</html>" },
      [ipify6]: { body: '{"ip":"8.8.8.8"}' }, [cloudflare6]: { body: "ip=2606:4700::1\nip=2606:4700::2\n" } });
    const result = await detectPublicAddresses({}, mock.transport);
    expect(result.preferredAddress).toBeNull(); expect(result.source).toEqual({ ipv4: null, ipv6: null });
    expect(result.warnings.join(" ")).toContain("手动输入");
  });
  test("oversized and malformed high-level mock responses are rejected too", async () => {
    const huge = JSON.stringify({ ip: "8.8.8.8", extra: "x".repeat(4096) });
    const mock = probeMock({ [ipify4]: { body: huge }, [aws4]: { body: "8.8.8.8".repeat(1000) }, [ipify6]: { body: "invalid JSON" }, [cloudflare6]: { body: "ip=fe80::1" } });
    expect((await detectPublicAddresses({}, mock.transport)).preferredAddress).toBeNull();
  });
  test("pre-cancelled operation never calls a transport", async () => {
    const controller = new AbortController(); controller.abort();
    const mock = probeMock({}); const result = await detectPublicAddresses({ signal: controller.signal }, mock.transport);
    expect(mock.calls).toHaveLength(0); expect(result.cancelled).toBe(true); expect(result.preferredAddress).toBeNull();
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
  test("cancellation closes all in-flight requests and removes the caller listener", async () => {
    const controller = new AbortController(), mock = probeMock(Object.fromEntries([ipify4, aws4, ipify6, cloudflare6].map(url => [url, { hang: true }])));
    const pending = detectPublicAddresses({ signal: controller.signal }, mock.transport);
    expect(mock.calls).toHaveLength(4); controller.abort(); const result = await pending;
    expect(result.cancelled).toBe(true); expect(result.preferredAddress).toBeNull();
    expect(mock.calls.every(call => call.aborted && call.finished)).toBe(true);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
  test("total deadline still completes if a mock transport ignores cancellation", async () => {
    const result = await detectPublicAddresses({ timeoutMs: 20 }, async () => new Promise<string>(() => {}));
    expect(result.cancelled).toBe(false); expect(result.preferredAddress).toBeNull();
    expect(result.warnings.join(" ")).toContain("未探测到");
  });
  test("IPv6 already obtained survives IPv4 deadline and gets selected", async () => {
    const mock = probeMock({ [ipify4]: { hang: true }, [aws4]: { hang: true }, [ipify6]: { body: '{"ip":"2a01:4f9::1"}' }, [cloudflare6]: { hang: true } });
    const result = await detectPublicAddresses({ timeoutMs: 25 }, mock.transport);
    expect(result.preferredAddress).toBe("2a01:4f9::1"); expect(result.cancelled).toBe(false);
    expect(mock.calls.every(call => call.finished)).toBe(true);
  });
  test("invalid timeout options do not initiate a request", async () => {
    const mock = probeMock({});
    for (const timeoutMs of [0, -1, 1.5, Infinity, 10_001]) await expect(detectPublicAddresses({ timeoutMs }, mock.transport)).rejects.toThrow("毫秒");
    expect(mock.calls).toHaveLength(0);
  });
});

describe("local interface candidates", () => {
  test("keeps marked LAN/shared/link-local candidates, prefers public IPs, and excludes loopback/invalid entries", () => {
    const item = (address: string, internal = false): os.NetworkInterfaceInfo => ({ address, internal, family: address.includes(":") ? "IPv6" : "IPv4", netmask: "", mac: "", cidr: null, scopeid: 0 }) as os.NetworkInterfaceInfo;
    const interfaces = {
      lo: [item("127.0.0.1", true), item("::1", true), item("127.1.2.3")],
      eth0: [item("192.168.10.5"), item("45.32.22.10"), item("2A01:4F9::1"), item("fd12:3456::1"), item("fe80::1"), item("0.0.0.0"), item("203.0.113.8")],
      duplicate: [item("45.32.22.10")], modem: [item("100.64.1.2")], wifi: [item("169.254.10.5")], empty: undefined,
    };
    const candidates = listLocalAddresses(interfaces);
    expect(candidates.filter(candidate => candidate.scope === "public").map(candidate => candidate.address)).toEqual(["45.32.22.10", "2a01:4f9::1"]);
    expect(candidates.find(candidate => candidate.address === "192.168.10.5")?.scope).toBe("private");
    expect(candidates.find(candidate => candidate.address === "fd12:3456::1")?.scope).toBe("private");
    expect(candidates.find(candidate => candidate.address === "100.64.1.2")?.scope).toBe("shared");
    expect(candidates.filter(candidate => candidate.scope === "link-local")).toHaveLength(2);
    expect(candidates).toHaveLength(7); expect(listLocalAddresses({})).toEqual([]);
  });
});

interface FakeResponse extends EventEmitter { statusCode: number; headers: Record<string, string>; complete: boolean; destroyed: boolean; destroy(): void }
interface FakeRequest extends EventEmitter { destroyed: boolean; ended: boolean; end(): void; destroy(): void }
type HttpScenario = (response: FakeResponse) => void;
function httpMock(scenario?: HttpScenario, statusCode = 200, headers: Record<string, string> = {}) {
  const calls: { url: URL; options: https.RequestOptions; req: FakeRequest; response: FakeResponse; agentDestroyed: number }[] = [];
  const request: AddressHttpsRequest = (url, options, onResponse) => {
    const response = Object.assign(new EventEmitter(), { statusCode, headers, complete: false, destroyed: false, destroy() { this.destroyed = true; } }) as FakeResponse;
    const req = Object.assign(new EventEmitter(), { destroyed: false, ended: false,
      end() { this.ended = true; if (scenario) queueMicrotask(() => { if (!this.destroyed) { onResponse(response as unknown as http.IncomingMessage); if (!response.destroyed) scenario(response); } }); },
      destroy() { this.destroyed = true; },
    }) as FakeRequest;
    const call = { url, options, req, response, agentDestroyed: 0 }; calls.push(call);
    const agent = options.agent as https.Agent, destroyAgent = agent.destroy.bind(agent);
    agent.destroy = () => { call.agentDestroyed++; destroyAgent(); };
    return req as unknown as http.ClientRequest;
  };
  return { transport: createHttpsAddressTransport(request), calls };
}
function transportOptions(signal: AbortSignal = new AbortController().signal): AddressTransportRequest { return { url: aws4, family: 4, signal, timeoutMs: 30, maxBodyBytes: 64 }; }
function endBody(response: FakeResponse, ...chunks: (string | Buffer)[]) { for (const chunk of chunks) { if (response.destroyed) return; response.emit("data", typeof chunk === "string" ? Buffer.from(chunk) : chunk); } response.complete = true; response.emit("end"); }

describe("direct HTTPS transport using only mock request/response streams", () => {
  test("does not inherit env/global proxies or send credentials; joins bounded chunks and closes resources", async () => {
    const previous = { HTTP_PROXY: process.env.HTTP_PROXY, HTTPS_PROXY: process.env.HTTPS_PROXY, NODE_USE_ENV_PROXY: process.env.NODE_USE_ENV_PROXY };
    process.env.HTTP_PROXY = "http://user:must-not-send@proxy.invalid:8888"; process.env.HTTPS_PROXY = process.env.HTTP_PROXY; process.env.NODE_USE_ENV_PROXY = "1";
    try {
      const controller = new AbortController(), mock = httpMock(response => endBody(response, "8.8.", "8.8\n"));
      expect(await mock.transport(transportOptions(controller.signal))).toBe("8.8.8.8\n");
      const call = mock.calls[0]!; expect(call.url.href).toBe(aws4); expect(call.options.family).toBe(4); expect(call.options.method).toBe("GET");
      expect(call.options.rejectUnauthorized).toBe(true); expect(call.options.agent).not.toBe(https.globalAgent);
      expect((call.options.agent as https.Agent).options.proxyEnv).toEqual({});
      expect(JSON.stringify(call.options.headers)).not.toContain("must-not-send");
      expect(Object.keys(call.options.headers!)).toEqual(["Accept", "Accept-Encoding", "User-Agent"]);
      expect(call.req.ended && call.req.destroyed && call.response.destroyed).toBe(true); expect(call.agentDestroyed).toBe(1);
      expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
    } finally { for (const [name, value] of Object.entries(previous)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } }
  });
  test("enforces IPv6 on its own endpoint", async () => {
    const mock = httpMock(response => endBody(response, '{"ip":"2606:4700::1"}'));
    await mock.transport({ ...transportOptions(), url: ipify6, family: 6 }); expect(mock.calls[0]!.options.family).toBe(6);
  });
  test("rejects redirects without following their Location", async () => {
    const mock = httpMock(() => {}, 302, { location: "http://169.254.169.254/latest/meta-data/" });
    await expect(mock.transport(transportOptions())).rejects.toThrow("HTTP 302");
    expect(mock.calls).toHaveLength(1); expect(mock.calls[0]!.response.destroyed).toBe(true);
  });
  test("rejects oversized declared bodies before reading data", async () => {
    let read = false; const mock = httpMock(() => { read = true; }, 200, { "content-length": "1000000" });
    await expect(mock.transport(transportOptions())).rejects.toThrow("过大"); expect(read).toBe(false);
    expect(mock.calls[0]!.agentDestroyed).toBe(1);
  });
  test("rejects oversized streaming bodies even without Content-Length", async () => {
    const mock = httpMock(response => endBody(response, "x".repeat(40), "y".repeat(40)));
    await expect(mock.transport(transportOptions())).rejects.toThrow("过大"); expect(mock.calls[0]!.req.destroyed).toBe(true);
  });
  test("rejects compressed and inconsistent response lengths", async () => {
    const compressed = httpMock(() => {}, 200, { "content-encoding": "gzip" });
    await expect(compressed.transport(transportOptions())).rejects.toThrow("压缩");
    const truncated = httpMock(response => endBody(response, "8.8.8.8"), 200, { "content-length": "20" });
    await expect(truncated.transport(transportOptions())).rejects.toThrow("不匹配");
  });
  test("bounds a request that never gets a response, including DNS/TLS waits", async () => {
    const mock = httpMock(); await expect(mock.transport(transportOptions())).rejects.toThrow("超时");
    expect(mock.calls[0]!.req.destroyed).toBe(true); expect(mock.calls[0]!.agentDestroyed).toBe(1);
  });
  test("bounds a slow response that never finishes", async () => {
    const mock = httpMock(response => response.emit("data", Buffer.from("8.8.")));
    await expect(mock.transport(transportOptions())).rejects.toThrow("超时"); expect(mock.calls[0]!.response.destroyed).toBe(true);
  });
  test("handles response abort, early close and errors without returning partial data", async () => {
    for (const event of ["aborted", "close", "error"]) {
      const mock = httpMock(response => { response.emit("data", Buffer.from("8.8.8.8")); response.emit(event, new Error("mock")); });
      await expect(mock.transport(transportOptions())).rejects.toThrow(); expect(mock.calls[0]!.agentDestroyed).toBe(1);
    }
  });
  test("explicit abort destroys an unfinished request and removes the signal listener", async () => {
    const controller = new AbortController(), mock = httpMock();
    const pending = mock.transport(transportOptions(controller.signal)); controller.abort();
    await expect(pending).rejects.toThrow("取消"); expect(mock.calls[0]!.req.destroyed).toBe(true);
    expect(mock.calls[0]!.agentDestroyed).toBe(1); expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
  test("rejects pre-abort and unlisted URL/family pairs before sending a request", async () => {
    const mock = httpMock(); const controller = new AbortController(); controller.abort();
    await expect(mock.transport(transportOptions(controller.signal))).rejects.toThrow("取消");
    for (const url of ["http://checkip.amazonaws.com/", "https://user:password@api.ipify.org/", "https://127.0.0.1/", "https://checkip.amazonaws.com/extra"]) await expect(mock.transport({ ...transportOptions(), url })).rejects.toThrow("列表");
    await expect(mock.transport({ ...transportOptions(), family: 6 })).rejects.toThrow("列表"); expect(mock.calls).toHaveLength(0);
  });
});
