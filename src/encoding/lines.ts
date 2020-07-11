import {assert} from '../internal/assert';

/*
 * Lines
 */

export function* lines(str: string): Generator<[number, string]> {
  assert(typeof str === 'string');

  let i = 0;
  let j = 0;
  let n = 0;

  if (str.length > 0) {
    if (str.charCodeAt(0) === 0xfeff) {
      i += 1;
      j += 1;
    }
  }

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x0d /*'\r'*/:
      case 0x0a /*'\n'*/:
      case 0x85 /*NEL*/: {
        if (j !== i) {
          const line = trimSpace(str.substring(j, i));

          if (line.length > 0) yield [n, line];
        }

        if (ch === 0x0d && i + 1 < str.length) {
          if (str.charCodeAt(i + 1) === 0x0a) i += 1;
        }

        j = i + 1;
        n += 1;

        break;
      }
    }
  }

  if (j !== i) {
    const line = trimSpace(str.substring(j, i));

    if (line.length > 0) yield [n, line];
  }
}

/*
 * Helpers
 */

function trimSpace(str: string) {
  assert(typeof str === 'string');

  for (let i = str.length - 1; i >= 0; i--) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09 /*'\t'*/:
      case 0x0b /*'\v'*/:
      case 0x0c /*'\f'*/:
      case 0x20 /*' '*/:
      case 0xa0 /*nbsp*/:
        continue;
    }

    return str.substring(0, i + 1);
  }

  return str;
}
