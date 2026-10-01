type Files = Record<string, string>;
const byId = (files: Files) =>
  Object.fromEntries(
    Object.entries(files).map(([path, text]) => [path.split('/').at(-2), text]),
  ) as Record<string, string>;

const code = byId(
  import.meta.glob('../../snippets/*/main.c', { query: '?raw', import: 'default', eager: true }),
);
const client = byId(
  import.meta.glob('../../snippets/*/client.go', { query: '?raw', import: 'default', eager: true }),
);
const golden = byId(
  import.meta.glob('../../snippets/*/golden.txt', { query: '?raw', import: 'default', eager: true }),
);

export interface Example {
  code: string;
  client?: string;
  golden: string;
}

export const exampleIds = Object.keys(code);

export function getExample(id: string): Example {
  if (!(id in code) || !(id in golden)) throw new Error(`unknown example id: ${id}`);
  return { code: code[id], client: client[id], golden: golden[id] };
}

export interface Section {
  cmd: string;
  out: string;
}

/** golden.txt is a sequence of "$ <command>" lines, each followed by that
 * command's (normalized) output. */
export function splitGolden(text: string): Section[] {
  return text
    .split(/^\$ /m)
    .slice(1)
    .map((chunk) => {
      const nl = chunk.indexOf('\n');
      const cmd = nl < 0 ? chunk : chunk.slice(0, nl);
      return { cmd, out: nl < 0 ? '' : chunk.slice(nl + 1).replace(/\n$/, '') };
    });
}
