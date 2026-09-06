import { describe, expect, it } from 'vitest';
import { compareIpKeys, deviceIpSortKey, ipSortKey } from './ipSort';

describe('numeric device IP order', () => {
  const sort = (values: string[], descending = false) => [...values].sort((a, b) => compareIpKeys(ipSortKey(a), ipSortKey(b), descending));
  it('orders octets numerically and keeps unknown addresses last in both directions', () => {
    const input = ['', '192.168.1.100', '192.168.1.2', '192.168.1.10', 'not an IP'];
    expect(sort(input)).toEqual(['192.168.1.2', '192.168.1.10', '192.168.1.100', '', 'not an IP']);
    expect(sort(input, true)).toEqual(['192.168.1.100', '192.168.1.10', '192.168.1.2', '', 'not an IP']);
  });
  it('handles compressed IPv6, embedded IPv4, and equivalent spellings', () => {
    expect(sort(['2001:db8::10', '2001:db8::2', '192.168.1.1'])).toEqual(['192.168.1.1', '2001:db8::2', '2001:db8::10']);
    expect(compareIpKeys(ipSortKey('fe80::1%20'), ipSortKey('fe80:0:0:0:0:0:0:1'))).toBe(0);
    expect(compareIpKeys(ipSortKey('::ffff:192.168.1.2'), ipSortKey('::ffff:c0a8:0102'))).toBe(0);
  });
  it('uses the lowest known address even when the upstream list is unsorted', () => {
    expect(deviceIpSortKey(['fe80::1', '192.168.1.12', '192.168.1.2'])).toEqual(ipSortKey('192.168.1.2'));
    expect(deviceIpSortKey(['invalid'])).toBeNull();
  });
  it('rejects malformed values without throwing', () => {
    for (const value of ['256.1.1.1', '1.2.3', ':', '1::2::3', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8::', 'gg::1']) {
      expect(ipSortKey(value)).toBeNull();
    }
  });
});
