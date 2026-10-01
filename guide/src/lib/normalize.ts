/** Make a run's output comparable across runs: only values that change per
 * run (timestamps, the port actually used) are masked; everything the page
 * wants to show stays verbatim. */
export function normalize(text: string, port: number): string {
  const body = text
    .replace(/\r\n/g, '\n')
    .replace(/\b\d{9,}\.\d{9}\b/g, '<ts>')
    .replaceAll(`127.0.0.1:${port}`, '127.0.0.1:4433')
    .replaceAll(`--port ${port}`, '--port 4433')
    .replace(/[ \t]+$/gm, '')
    .replace(/\n+$/, '');
  return body ? `${body}\n` : '';
}
