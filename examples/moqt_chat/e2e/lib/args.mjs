/** The hub's UDP port for every e2e run: WIRED_E2E_PORT moves it off 4433
 * (a host may already run a hub there -- SO_REUSEPORT lets a second bind
 * succeed and steal its packets). */
export const E2E_PORT = Number(process.env.WIRED_E2E_PORT ?? 4433);
export const E2E_SERVER_URL = `https://localhost:${E2E_PORT}/`;

/** Points the join form's server URL at E2E_SERVER_URL (the page defaults
 * to 4433). */
export async function setServerUrl(page) {
  await page.$eval(
    'input[data-testid="url"]',
    (el, v) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    E2E_SERVER_URL,
  );
}

/** `--name=value` lookup over process.argv, with a fallback when absent. */
export function arg(name, fallback) {
  const flag = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(flag));
  return found ? found.slice(flag.length) : fallback;
}
