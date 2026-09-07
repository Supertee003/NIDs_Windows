/**
 * ts_policy/tests/typed_values.test.ts
 *
 * T6 AC: "IR supports the typed value set" (IPv4, IPv6, CIDR, string,
 * enum, integer, time, domain, process, file, identity).
 *
 * Each typed-value constructor is tested for:
 *   1. Valid input produces the correct { kind, value } shape.
 *   2. Invalid input throws.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  ipv4,
  ipv6,
  cidr,
  port,
  time,
  domain,
  process_,
  file,
  identity,
} from "../src/types.js";

test("ipv4: accepts valid dotted-quad", () => {
  assert.deepEqual(ipv4("10.0.0.1"), { kind: "ipv4", value: "10.0.0.1" });
  assert.deepEqual(ipv4("255.255.255.255"), { kind: "ipv4", value: "255.255.255.255" });
  assert.deepEqual(ipv4("0.0.0.0"), { kind: "ipv4", value: "0.0.0.0" });
});

test("ipv4: rejects non-dotted-quad", () => {
  assert.throws(() => ipv4("10.0.0"));
  assert.throws(() => ipv4("10.0.0.1.2"));
  assert.throws(() => ipv4("hello"));
});

test("ipv4: rejects out-of-range octets", () => {
  assert.throws(() => ipv4("256.0.0.0"));
  assert.throws(() => ipv4("-1.0.0.0"));
  assert.throws(() => ipv4("10.0.0.999"));
});

test("ipv6: accepts addresses with colons", () => {
  assert.deepEqual(ipv6("::1"), { kind: "ipv6", value: "::1" });
  assert.deepEqual(ipv6("fe80::1"), { kind: "ipv6", value: "fe80::1" });
  assert.deepEqual(ipv6("2001:db8::1"), { kind: "ipv6", value: "2001:db8::1" });
});

test("ipv6: rejects non-IPv6", () => {
  assert.throws(() => ipv6("10.0.0.1"));
  assert.throws(() => ipv6("hello"));
});

test("cidr: accepts valid IPv4 CIDR", () => {
  assert.deepEqual(cidr("10.0.0.0/24"), { kind: "cidr", value: "10.0.0.0/24" });
  assert.deepEqual(cidr("0.0.0.0/0"), { kind: "cidr", value: "0.0.0.0/0" });
  assert.deepEqual(cidr("192.168.1.0/32"), { kind: "cidr", value: "192.168.1.0/32" });
});

test("cidr: rejects missing prefix or out-of-range", () => {
  assert.throws(() => cidr("10.0.0.0"));
  assert.throws(() => cidr("10.0.0.0/33"));
  assert.throws(() => cidr("10.0.0.0/-1"));
  assert.throws(() => cidr("not-an-ip/24"));
});

test("port: accepts 0..65535", () => {
  assert.deepEqual(port(0), { kind: "integer", value: 0 });
  assert.deepEqual(port(80), { kind: "integer", value: 80 });
  assert.deepEqual(port(65535), { kind: "integer", value: 65535 });
});

test("port: rejects out-of-range or non-integer", () => {
  assert.throws(() => port(-1));
  assert.throws(() => port(65536));
  assert.throws(() => port(1.5));
  assert.throws(() => port(NaN));
});

test("time: accepts finite epoch ms", () => {
  assert.deepEqual(time(0), { kind: "time", value: 0 });
  assert.deepEqual(time(1_700_000_000_000), { kind: "time", value: 1_700_000_000_000 });
});

test("time: rejects NaN / Infinity", () => {
  assert.throws(() => time(NaN));
  assert.throws(() => time(Infinity));
  assert.throws(() => time(-Infinity));
});

test("domain: accepts valid FQDN-like", () => {
  assert.deepEqual(domain("evil.example"), { kind: "domain", value: "evil.example" });
  assert.deepEqual(domain("a.b.c.d"), { kind: "domain", value: "a.b.c.d" });
});

test("domain: rejects empty or whitespace", () => {
  assert.throws(() => domain(""));
  assert.throws(() => domain("evil example.com"));
  assert.throws(() => domain("trailing-space "));
});

test("process_: accepts process name and path", () => {
  assert.deepEqual(process_("ls"), { kind: "process", value: "ls" });
  assert.deepEqual(process_("C:\\Windows\\System32\\cmd.exe"), {
    kind: "process",
    value: "C:\\Windows\\System32\\cmd.exe",
  });
});

test("file: accepts non-empty file path", () => {
  assert.deepEqual(file("/etc/passwd"), { kind: "file", value: "/etc/passwd" });
  assert.deepEqual(file("C:\\Windows\\System32\\drivers\\etc\\hosts"), {
    kind: "file",
    value: "C:\\Windows\\System32\\drivers\\etc\\hosts",
  });
});

test("file: rejects empty", () => {
  assert.throws(() => file(""));
});

test("identity: accepts user/sid/token", () => {
  assert.deepEqual(identity("DOMAIN\\user"), { kind: "identity", value: "DOMAIN\\user" });
  assert.deepEqual(identity("S-1-5-21-..."), { kind: "identity", value: "S-1-5-21-..." });
});

test("identity: rejects empty", () => {
  assert.throws(() => identity(""));
});
