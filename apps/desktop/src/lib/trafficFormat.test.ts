import {expect,it} from 'vitest';
import {formatBytes,trafficCsv,trafficPath} from './trafficFormat';
it('keeps spreadsheet exports inert and correctly escapes quotes and newlines',()=>{
  const csv=trafficCsv([['=IMPORTXML("https://example.invalid")','+cmd','normal, name','line\nbreak']]);
  expect(csv).toContain('"\'=IMPORTXML(""https://example.invalid"")"');expect(csv).toContain('"\'+cmd"');expect(csv).toContain('"normal, name"');expect(csv).toContain('"line\nbreak"');
});
it('leaves measurement gaps visible and distinguishes unavailable values from zero',()=>{
  expect(formatBytes(null)).toBe('Not measured');expect(formatBytes(0)).toBe('0 B');
  const path=trafficPath([{at:100,sent_bytes:50,received_bytes:100,measured_ms:60000},{at:160,sent_bytes:20,received_bytes:100,measured_ms:60000},{at:400,sent_bytes:20,received_bytes:100,measured_ms:60000}],'received_bytes',100,400,100,60);
  expect((path.match(/M/g)||[]).length).toBe(2);expect(path).toContain('L180.00');
});
