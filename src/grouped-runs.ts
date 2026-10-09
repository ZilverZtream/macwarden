/** A grouped run: its start offset in the text and the matched characters. */
export type GroupedRun = { index: number; value: string };

/**
 * The leftmost-greedy matches of the regular expression `W+(?:SW+)+={0,2}` (global),
 * for disjoint single-character classes W (word) and S (separator) that both exclude
 * '='. The regular expression backtracks from every start inside a long word run that
 * has no separator, which is quadratic; this single pass is linear and returns exactly
 * the same matches: a match can only start at the beginning of a word run, and only if
 * that whole run is followed by a separator and another word character.
 */
export function groupedRuns(text: string, isWord: (character: string) => boolean,
  isSeparator: (character: string) => boolean): GroupedRun[] {
  const runs: GroupedRun[] = [];
  const length = text.length;
  let at = 0;
  while (at < length) {
    if (!isWord(text[at])) { at++; continue; }
    const start = at;
    while (at < length && isWord(text[at])) at++;
    let end = at;
    let groups = 1;
    while (end + 1 < length && isSeparator(text[end]) && isWord(text[end + 1])) {
      end++;
      while (end < length && isWord(text[end])) end++;
      groups++;
    }
    if (groups === 1) continue;
    let padding = 0;
    while (padding < 2 && text[end + padding] === '=') padding++;
    runs.push({ index: start, value: text.slice(start, end + padding) });
    at = end + padding;
  }
  return runs;
}

const base64Digit = (character: string) => /^[A-Za-z0-9+/]$/.test(character);

/** The three grouped base64 shapes the credential recogniser and leak check decode. */
export const groupedBase64 = {
  /** Groups joined by '-': word [A-Za-z0-9+/_]. */
  dash: (text: string) => groupedRuns(text, character => base64Digit(character) || character === '_',
    character => character === '-'),
  /** Groups joined by '_': word [A-Za-z0-9+/]. */
  underscore: (text: string) => groupedRuns(text, base64Digit, character => character === '_'),
  /** Groups joined by any other single character: word [A-Za-z0-9+/_-]. */
  other: (text: string) => groupedRuns(text, character => base64Digit(character) || character === '_' || character === '-',
    character => !/^[A-Za-z0-9+/_=\s\\-]$/.test(character)),
};
