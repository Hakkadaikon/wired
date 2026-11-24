import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

// D-29: the UI is English only. Kana, CJK ideographs/punctuation and
// full-width forms anywhere in src/ (tests excepted) fail the build.
// CJK symbols, kana and compatibility, Ext. A, unified, compatibility
// ideographs, full-width forms, and the supplementary ideograph planes
const CJK =
	/[\u3000-\u33ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef\u{20000}-\u{2ffff}]/u;
const SRC = path.resolve(__dirname, "../..");

function sources(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) return e.name === "__tests__" ? [] : sources(p);
		return [p];
	});
}

describe("no Japanese in the UI", () => {
	it("the pattern catches every listed range, not English punctuation", () => {
		// Code points, not literals: the formatter would inline the characters.
		const hit = [0x3042, 0x3300, 0x4e00, 0xf900, 0xff21, 0x20b9f];
		for (const cp of hit) expect(CJK.test(String.fromCodePoint(cp))).toBe(true);
		const miss = [0x2026, 0x2713, 0x22ef, 0xb7, 0x2fff];
		for (const cp of miss)
			expect(CJK.test(String.fromCodePoint(cp))).toBe(false);
	});

	it("no src file outside __tests__ contains CJK or kana", () => {
		const files = sources(SRC);
		expect(files.length).toBeGreaterThan(0);
		const hits = files.flatMap((f) =>
			readFileSync(f, "utf8")
				.split("\n")
				.flatMap((line, i) =>
					CJK.test(line) ? [`${path.relative(SRC, f)}:${i + 1}`] : [],
				),
		);
		expect(hits).toEqual([]);
	});
});
