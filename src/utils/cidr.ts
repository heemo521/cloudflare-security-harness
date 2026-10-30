/**
 * IPv4/IPv6 CIDR matching without dependencies.
 */

function parseIPv4(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

function parseIPv6(ip: string): bigint | null {
  // Strip brackets and zone id.
  ip = ip.replace(/^\[|\]$/g, "").split("%")[0];
  // Embedded IPv4 such as ::ffff:1.2.3.4
  const v4tail = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4tail) {
    const v4 = parseIPv4(v4tail[2]);
    if (v4 === null) return null;
    const hi = (v4 >> 16n).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    ip = `${v4tail[1]}${hi}:${lo}`;
  }
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(missing).fill("0"), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

export interface ParsedIp {
  family: 4 | 6;
  value: bigint;
}

export function parseIp(ip: string): ParsedIp | null {
  const trimmed = ip.trim();
  if (trimmed.includes(":")) {
    const v = parseIPv6(trimmed);
    return v === null ? null : { family: 6, value: v };
  }
  const v = parseIPv4(trimmed);
  return v === null ? null : { family: 4, value: v };
}

/** True when `ip` falls within `cidr` (or equals it when no prefix length is given). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [net, prefixStr] = cidr.trim().split("/");
  const target = parseIp(ip);
  const network = parseIp(net);
  if (!target || !network || target.family !== network.family) return false;
  const bits = target.family === 4 ? 32 : 128;
  const prefix = prefixStr === undefined ? bits : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return false;
  if (prefix === 0) return true;
  const shift = BigInt(bits - prefix);
  return target.value >> shift === network.value >> shift;
}

/** Returns the first matching CIDR, or null. */
export function ipInAnyCidr(ip: string, cidrs: string[]): string | null {
  for (const c of cidrs) if (ipInCidr(ip, c)) return c;
  return null;
}
