# Third-party components and references

NexusEdge 2.3.0 launches upstream cores as separate processes. This source
archive contains no Bun, Xray, sing-box, cloudflared, or libcronet binaries.
First-use defaults have pinned official URLs, archive hashes, and extracted file
hashes in `src/network.ts`. Explicit updates query the same official repositories
through GitHub Releases, require the release asset's SHA256 digest, and record
file hashes after the downloaded archive is verified. Selected versions persist
independently of future controller updates. Upstream licenses and notices remain applicable.

| Component | Role | Upstream |
| --- | --- | --- |
| Bun >= 1.4.3 | TypeScript runtime; system install copies the user's runtime | <https://github.com/oven-sh/bun> |
| Xray 26.3.27 | VLESS, transports, REALITY / ENC, WireGuard egress | <https://github.com/XTLS/Xray-core/releases/tag/v26.3.27> |
| sing-box 1.14.3 | Other node protocols, WireGuard endpoint | <https://github.com/SagerNet/sing-box/releases/tag/v1.14.3> |
| cloudflared 2026.10.2 | Optional per-node HTTP Tunnel connector | <https://github.com/cloudflare/cloudflared/releases/tag/2026.10.2> |
| TypeScript 5.9.3 | Development-only type checking | <https://github.com/microsoft/TypeScript> |
| @types/bun 1.4.3 | Development-only declarations | <https://github.com/oven-sh/bun> |

All three default core releases were rechecked against their official
`/releases/latest` responses on 2026-10-21 with `draft=false` and
`prerelease=false`. Xray v26.10.17 is an upstream prerelease and is no longer a
first-use default. Persisted selections remain unchanged when the controller is
replaced. Runtime does not automatically follow future tags; the core management
menu supports stable updates, explicit previews, specified versions, and rollback.

The stable label does not mean a release contains every later fix. The upstream
advisory <https://github.com/XTLS/Xray-core/security/advisories/GHSA-5wf9-h793-w73c>
includes Xray 26.3.27 in its affected version range: the described client case
combines a CA certificate pin with an empty `serverName` on Hy2 / gRPC. Generated
Xray clients here set a nonempty server name and, when applicable, pin the server
certificate; Hysteria2 uses sing-box. Hand-edited external client configurations
must be assessed separately.

Release licenses and required bundled dependencies listed in the manifest are
retained and hash-checked, including sing-box's libcronet for Naive. See upstream
repositories and releases for complete terms and notices.

Core update metadata and archive verification reference:
<https://docs.github.com/en/rest/releases/assets>. GitHub's HTTPS metadata binds
the downloaded archive to its reported digest; it is not an independent publisher
signature. Future upstream package layouts or configuration changes can require
a controller update. Version checks do not send node configuration or credentials.

The best-effort WARP registration flow follows the client API shape used by wgcf
at commit `803310a27bf040ac831b74cf3b4b993482f48647`:
<https://github.com/ViRb3/wgcf/blob/803310a27bf040ac831b74cf3b4b993482f48647/cloudflare/api.go>.
This is not a Cloudflare compatibility commitment for third-party use. Existing
valid WireGuard profiles can be imported instead.

Protocol and feature references:

- Xray VLESS: <https://xtls.github.io/config/inbounds/vless.html>
- Xray TLS / REALITY: <https://xtls.github.io/config/transport.html>
- sing-box configuration: <https://sing-box.sagernet.org/configuration/>
- Shadowsocks SIP002: <https://shadowsocks.org/doc/sip002.html>
- Cloudflare Tunnel: <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/>
- Quick Tunnel: <https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/>

Operating-system firewall interfaces used by the controller:

- Microsoft NetSecurity / New-NetFirewallRule: <https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule>
- Windows Firewall rule behavior and policy: <https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules>
- UFW manual: <https://manpages.ubuntu.com/manpages/resolute/man8/ufw.8.html>
- firewalld rich rules: <https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html>
- firewalld runtime and permanent configuration: <https://firewalld.org/documentation/configuration/runtime-versus-permanent.html>
- Netfilter iptables: <https://man7.org/linux/man-pages/man8/iptables.8.html>
- nftables chain verdict semantics: <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>

Firewall rules manage finite local inbound ports, separately from protocol cores.
No firewall binaries are redistributed. The controller preserves unrelated rules,
does not enable a disabled firewall, and does not change cloud security groups or
router NAT. Tests substitute OS command execution; native Windows policy and
remote reachability require validation on the target machine.

The optional public-address lookup sends credential-free HTTPS requests to
fixed ipify, AWS CheckIP and Cloudflare trace endpoints. Documentation:

- <https://www.ipify.org/>
- <https://docs.aws.amazon.com/batch/latest/userguide/create-a-base-security-group.html>
- <https://developers.cloudflare.com/privacy-proxy/get-started/>
- <https://www.iana.org/assignments/iana-ipv4-special-registry/>
- <https://www.iana.org/assignments/iana-ipv6-special-registry/>

The lookup reports an outbound address candidate, not an inbound reachability
guarantee. System VPN/TUN routes can still affect it. No node credentials,
tokens, certificate material or application configuration are sent.

NexusEdge is an independent controller. The core projects maintain their own
releases, licenses, and support channels.
