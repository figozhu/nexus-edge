import { expect, test } from "bun:test";
import * as realUpdatesFs from "node:fs";
import * as realUpdatesPath from "node:path";
import * as realUpdatesOs from "node:os";
import * as realUpdatesNet from "node:net";
import * as realUpdatesDgram from "node:dgram";
import { type DaemonStatus, createPaths, createDefaultNode, defaultConfig, writeConfig } from "../src/core.ts";
import { type CoreReleaseCandidate, coreBinaryPath, coreReleaseFingerprint, ensureBinaries, readCoreSelection } from "../src/network.ts";
import { getDaemonStatus, startDetachedDaemon, stopDaemonGracefully, tailLog, waitForReady } from "../src/daemon.ts";
import { applyCoreUpdates, rollbackCoreUpdates } from "../src/updates.ts";

const realUpdatesArchive = process.env.NEXUS_EDGE_TEST_SINGBOX_ARCHIVE;
const realUpdatesBinary = process.env.NEXUS_EDGE_SINGBOX_TEST_BINARY;
const realUpdatesAvailable = process.platform === "linux" && realUpdatesArchive && realUpdatesBinary && realUpdatesFs.existsSync(realUpdatesArchive) && realUpdatesFs.existsSync(realUpdatesBinary);

interface RealUpdatesProcess { pid: number; parent: number; start: string; state: string; argv: string[]; executable: string }

/** Only inspect a worker returned by this test's authenticated control endpoint and its descendants. */
function realUpdatesProcess(pid: number): RealUpdatesProcess | null {
  try {
    const stat = realUpdatesFs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return { pid, parent: Number(fields[1]), start: fields[19]!, state: fields[0]!, argv: realUpdatesFs.readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean), executable: realUpdatesFs.readlinkSync(`/proc/${pid}/exe`) };
  } catch { return null; }
}

function realUpdatesTree(pid: number, observations: string): RealUpdatesProcess[] {
  const records = realUpdatesFs.existsSync(observations) ? realUpdatesFs.readFileSync(observations, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line) as { parent: number; pid: number; executable: string }) : [];
  const queue = [pid], seen = new Set<number>(), result: RealUpdatesProcess[] = [];
  while (queue.length) {
    const next = queue.shift()!;
    if (seen.has(next)) continue;
    if (seen.size >= 32) throw new Error("Unexpectedly large real-updater worker subtree");
    seen.add(next);
    const process = realUpdatesProcess(next);
    if (process) {
      result.push(process);
      // The fixture observes unchanged real spawn calls. Recheck the actual
      // parent PID before following a recorded edge or reading a child's exe.
      for (const record of records.filter(record => record.parent === next)) {
        const child = realUpdatesProcess(record.pid);
        if (child?.parent === next) queue.push(record.pid);
      }
    }
  }
  return result;
}

function realUpdatesStillAlive(process: RealUpdatesProcess): boolean {
  const current = realUpdatesProcess(process.pid);
  return Boolean(current && current.start === process.start && current.state !== "Z");
}

async function realUpdatesUntil(testCondition: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!testCondition()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for this test's owned processes to exit");
    await Bun.sleep(25);
  }
}

async function realUpdatesPort(): Promise<number> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const tcp = realUpdatesNet.createServer(), udp = realUpdatesDgram.createSocket("udp4");
    let tcpOpen = false, udpOpen = false;
    try {
      await new Promise<void>((resolve, reject) => { tcp.once("error", reject); tcp.listen(0, "127.0.0.1", () => { tcpOpen = true; resolve(); }); });
      const address = tcp.address(); if (!address || typeof address === "string") throw new Error("Missing loopback test address");
      await new Promise<void>((resolve, reject) => { udp.once("error", reject); udp.bind(address.port, "127.0.0.1", () => { udpOpen = true; resolve(); }); });
      return address.port;
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EADDRINUSE" || attempt === 4) throw error; }
    finally {
      if (udpOpen) await new Promise<void>(resolve => udp.close(resolve));
      if (tcpOpen) await new Promise<void>(resolve => tcp.close(() => resolve()));
    }
  }
  throw new Error("No free loopback TCP/UDP port found");
}

(realUpdatesAvailable ? test : test.skip)("real Linux updater switches the worker's selected sing-box executable and rolls back while preserving node credentials", async () => {
  const root = realUpdatesFs.mkdtempSync(realUpdatesPath.join(realUpdatesOs.tmpdir(), "nexus-real-updates-"));
  const entry = realUpdatesPath.join(import.meta.dir, "fixtures", "real-update-entry.ts");
  const paths = { ...createPaths(realUpdatesPath.join(root, "nexus-edge.ts"), process.execPath), entry };
  const originalFetch = globalThis.fetch;
  const downloads: string[] = [], owned: RealUpdatesProcess[] = [];
  const config = defaultConfig(), node = createDefaultNode("shadowsocks");
  node.listen = "127.0.0.1"; node.address = "127.0.0.1";
  node.port = await realUpdatesPort(); node.publicPort = node.port;
  config.nodes.push(node); writeConfig(paths, config);
  const originalConfigBytes = realUpdatesFs.readFileSync(paths.config, "utf8");
  const bundled = readCoreSelection(paths).active.singBox;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== bundled.downloadUrl) throw new Error("This integration test must not contact an external service");
    downloads.push(url); return new Response(Bun.file(realUpdatesArchive!));
  }) as typeof fetch;
  // Keep every controller boundary real except native service discovery.
  const operations = { getStartup: async () => ({ mode: "none" as const, enabled: false, running: false, detail: "Portable localhost integration fixture" }) };
  const observe = (status: DaemonStatus, executable: string): RealUpdatesProcess => {
    expect(status.phase).toBe("ready"); expect(status.nodes[0]?.listenerCheck).toBe("tcp+udp");
    expect(status.nodes[0]?.listenerReady).toBe(true); expect(status.nodes[0]?.directReady).toBe(true);
    expect(status.coreReleaseHash).toBe(coreReleaseFingerprint(readCoreSelection(paths).active));
    const tree = realUpdatesTree(status.pid, realUpdatesPath.join(root, "owned-spawns.jsonl")); owned.push(...tree);
    expect(tree[0]?.argv).toContain(entry); expect(tree[0]?.argv).toContain("--worker");
    const cores = tree.filter(child => child.executable === realUpdatesFs.realpathSync(executable));
    if (cores.length !== 1) throw new Error(`Expected one selected core ${executable}; owned process tree: ${JSON.stringify(tree)}; observations: ${realUpdatesFs.existsSync(realUpdatesPath.join(root, "owned-spawns.jsonl")) ? realUpdatesFs.readFileSync(realUpdatesPath.join(root, "owned-spawns.jsonl"), "utf8") : "none"}`);
    expect(cores).toHaveLength(1); expect(cores[0]!.argv.slice(1, 3)).toEqual(["run", "-c"]);
    expect(realUpdatesFs.readFileSync(paths.config, "utf8")).toBe(originalConfigBytes);
    return cores[0]!;
  };
  try {
    const installed = await ensureBinaries(paths, config);
    expect(Object.keys(installed)).toEqual(["singBox"]);
    const originalSelection = readCoreSelection(paths);
    const oldExecutable = coreBinaryPath(paths, originalSelection.active.singBox);
    expect(installed.singBox).toBe(oldExecutable);
    await startDetachedDaemon(paths);
    const first = await waitForReady(paths, 10000);
    if (!first || first.phase !== "ready") throw new Error("Initial real sing-box worker did not become ready");
    const firstCore = observe(first, oldExecutable);
    const originalLinks = structuredClone(first.links), originalLinkFile = realUpdatesFs.readFileSync(paths.link, "utf8");
    expect(first.links[0]?.uri).toStartWith("ss://");

    // This is the same verified official version with a downloaded-release receipt.
    // Its digest-suffixed path differs, proving selection controls the actual executable.
    const { files: _files, ...asset } = bundled.asset;
    const candidate: CoreReleaseCandidate = { ...bundled, source: "github", asset };
    const updated = await applyCoreUpdates(paths, [candidate], () => {}, operations, originalSelection);
    expect(updated.changed).toBe(true); expect(updated.restarted).toBe(true);
    const selected = readCoreSelection(paths), newExecutable = coreBinaryPath(paths, selected.active.singBox);
    expect(newExecutable).not.toBe(oldExecutable); expect(selected.active.singBox.source).toBe("github");
    expect(selected.previous).toEqual(originalSelection.active);
    const second = await getDaemonStatus(paths);
    if (!second) throw new Error("Updated worker has no authenticated status");
    const secondCore = observe(second, newExecutable);
    expect(second.instanceId).not.toBe(first.instanceId); expect(second.pid).not.toBe(first.pid);
    expect(secondCore.pid).not.toBe(firstCore.pid); expect(second.links).toEqual(originalLinks);
    expect(realUpdatesFs.readFileSync(paths.link, "utf8")).toBe(originalLinkFile);
    await realUpdatesUntil(() => !realUpdatesStillAlive(firstCore));

    const rolledBack = await rollbackCoreUpdates(paths, () => {}, operations, selected);
    expect(rolledBack.changed).toBe(true); expect(rolledBack.restarted).toBe(true);
    expect(readCoreSelection(paths).active).toEqual(originalSelection.active);
    const third = await getDaemonStatus(paths);
    if (!third) throw new Error("Rolled-back worker has no authenticated status");
    const thirdCore = observe(third, oldExecutable);
    expect(new Set([first.instanceId, second.instanceId, third.instanceId]).size).toBe(3);
    expect(new Set([first.pid, second.pid, third.pid]).size).toBe(3);
    expect(new Set([firstCore.pid, secondCore.pid, thirdCore.pid]).size).toBe(3);
    expect(third.links).toEqual(originalLinks); expect(realUpdatesFs.readFileSync(paths.link, "utf8")).toBe(originalLinkFile);
    expect(realUpdatesFs.existsSync(oldExecutable)).toBe(true); expect(realUpdatesFs.existsSync(newExecutable)).toBe(true);
    expect(downloads).toEqual([bundled.downloadUrl, bundled.downloadUrl]);
    await stopDaemonGracefully(paths);
    expect(await getDaemonStatus(paths)).toBeNull();
    await realUpdatesUntil(() => owned.every(process => !realUpdatesStillAlive(process)));
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${tailLog(paths, 16)}`);
  } finally {
    try { await stopDaemonGracefully(paths, 6000); }
    catch {
      // Only signals process identities observed from this test's own authenticated
      // worker tree; never uses an arbitrary persisted PID as a kill target.
      for (const process of owned) if (realUpdatesStillAlive(process)) { try { globalThis.process.kill(process.pid, "SIGTERM"); } catch {} }
      await realUpdatesUntil(() => owned.every(process => !realUpdatesStillAlive(process)), 7000).catch(() => {
        for (const process of owned) if (realUpdatesStillAlive(process)) { try { globalThis.process.kill(process.pid, "SIGKILL"); } catch {} }
      });
    }
    globalThis.fetch = originalFetch;
    realUpdatesFs.rmSync(root, { recursive: true, force: true });
  }
}, 45000);
