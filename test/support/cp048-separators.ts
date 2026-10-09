import type { Form } from './cp041-controls.js';
export const auditedForms: Form[] = [
  ...['+', '~', '#'].map(separator => ({ name: `hex separator ${separator}`,
    encode: (bytes: Buffer) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join(separator) })),
  ...['|', '-', '.'].map(separator => ({ name: `decimal separator ${separator}`,
    encode: (bytes: Buffer) => [...bytes].join(separator) })),
  { name: 'base64 grouped underscore', encode: bytes => bytes.toString('base64').match(/.{1,8}/g)!.join('_') },
  // 2026-10-07 audit: any non-alphanumeric byte separator and regular base64 grouping.
  ...['*', '=', '^'].map(separator => ({ name: `hex separator ${separator}`,
    encode: (bytes: Buffer) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join(separator) })),
  { name: 'upper-case hex separator !', encode: bytes => [...bytes].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('!') },
  ...['/', '_', '+'].map(separator => ({ name: `decimal separator ${separator}`,
    encode: (bytes: Buffer) => [...bytes].join(separator) })),
  { name: 'base64 grouped dot', encode: bytes => bytes.toString('base64').match(/.{1,4}/g)!.join('.') },
  { name: 'base64 grouped tilde', encode: bytes => bytes.toString('base64').match(/.{1,4}/g)!.join('~') },
  { name: 'base64 grouped by eight colon', encode: bytes => bytes.toString('base64').match(/.{1,8}/g)!.join(':') },
  { name: 'base64 grouped underscore after key=', encode: bytes => `alias=${bytes.toString('base64').match(/.{1,4}/g)!.join('_')}` },
];
