import { describe, expect, it } from "vitest";
import { ipInCidr, parseIp } from "../src/utils/cidr";

describe("cidr", () => {
  it("parses IPv4 and IPv6", () => {
    expect(parseIp("192.168.1.1")?.family).toBe(4);
    expect(parseIp("2001:db8::1")?.family).toBe(6);
    expect(parseIp("::ffff:10.0.0.1")?.family).toBe(6);
    expect(parseIp("999.1.1.1")).toBeNull();
    expect(parseIp("2001:db8:::1")).toBeNull();
    expect(parseIp("not-an-ip")).toBeNull();
  });

  it("matches IPv4 ranges", () => {
    expect(ipInCidr("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(ipInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("192.168.1.77", "192.168.1.0/24")).toBe(true);
    expect(ipInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
    expect(ipInCidr("1.2.3.4", "1.2.3.4")).toBe(true);
    expect(ipInCidr("1.2.3.5", "1.2.3.4/32")).toBe(false);
    expect(ipInCidr("8.8.8.8", "0.0.0.0/0")).toBe(true);
  });

  it("matches IPv6 ranges", () => {
    expect(ipInCidr("2001:db8:abcd::1", "2001:db8::/32")).toBe(true);
    expect(ipInCidr("2001:db9::1", "2001:db8::/32")).toBe(false);
    expect(ipInCidr("fe80::1%eth0", "fe80::/10")).toBe(true);
    expect(ipInCidr("[2001:db8::5]", "2001:db8::/64")).toBe(true);
  });

  it("never matches across families or with bad prefixes", () => {
    expect(ipInCidr("10.0.0.1", "::/0")).toBe(false);
    expect(ipInCidr("10.0.0.1", "10.0.0.0/33")).toBe(false);
    expect(ipInCidr("10.0.0.1", "garbage/8")).toBe(false);
  });
});
