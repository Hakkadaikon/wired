// Minimal assertion-based test runner. No framework, browser + Node compatible.
const results = [];

export function test(name, fn) {
  try {
    fn();
    results.push({ name, pass: true });
  } catch (err) {
    results.push({ name, pass: false, error: err.message || String(err) });
  }
}

export function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(
      `${msg || 'assertEqual failed'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

export function assertTrue(cond, msg) {
  if (!cond) {
    throw new Error(msg || 'assertTrue failed');
  }
}

export function assertThrows(fn, msg) {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(msg || 'assertThrows failed: no error thrown');
}

export function report() {
  const failed = results.filter((r) => !r.pass);
  for (const r of results) {
    console.log(`${r.pass ? 'PASS' : 'FAIL'} - ${r.name}${r.error ? `: ${r.error}` : ''}`);
  }
  console.log(`\n${results.length - failed.length}/${results.length} passed`);

  if (typeof document !== 'undefined') {
    const ul = document.createElement('ul');
    for (const r of results) {
      const li = document.createElement('li');
      li.textContent = `${r.pass ? 'PASS' : 'FAIL'} - ${r.name}${r.error ? `: ${r.error}` : ''}`;
      li.style.color = r.pass ? 'green' : 'red';
      ul.appendChild(li);
    }
    const summary = document.createElement('p');
    summary.textContent = `${results.length - failed.length}/${results.length} passed`;
    document.body.appendChild(ul);
    document.body.appendChild(summary);
  }

  return failed.length === 0;
}
