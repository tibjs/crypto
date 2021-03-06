export = <[string, Buffer, Buffer, Buffer, Buffer, Buffer, Buffer][]>[
  // alg, key, iv, pt, ct, tag, aad
  [
    'AES-128-CCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('12345678901234567'),
    Buffer.from('3e21f2abd8fbad18787c25b897f394953f', 'hex'),
    Buffer.from('75032cf4222d872a', 'hex'),
    Buffer.alloc(0),
  ],
  [
    'AES-128-CCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('1234567890123456'),
    Buffer.from('3e21f2abd8fbad18787c25b897f39495', 'hex'),
    Buffer.from('ce3866fa1148c868', 'hex'),
    Buffer.alloc(0),
  ],
  [
    'AES-128-CCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('1234567890123456'),
    Buffer.from('3e21f2abd8fbad18787c25b897f39495', 'hex'),
    Buffer.from('6dd8285171fa90cb963d0d15', 'hex'),
    Buffer.alloc(0),
  ],
  [
    'AES-128-GCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('12345678901234567'),
    Buffer.from('ab87d180fed656b1ab5c57233ce490de0e', 'hex'),
    Buffer.from('ccba2f88b733ab51', 'hex'),
    Buffer.alloc(0),
  ],
  [
    'AES-128-GCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('1234567890123456'),
    Buffer.from('ab87d180fed656b1ab5c57233ce490de', 'hex'),
    Buffer.from('dd6fef299471bbb9', 'hex'),
    Buffer.alloc(0),
  ],
  [
    'AES-128-GCM',
    Buffer.from('1234567890123456'),
    Buffer.from('1234567890123'),
    Buffer.from('1234567890123456'),
    Buffer.from('ab87d180fed656b1ab5c57233ce490de', 'hex'),
    Buffer.from('dd6fef299471bbb9a3c7639a', 'hex'),
    Buffer.alloc(0),
  ],
];
