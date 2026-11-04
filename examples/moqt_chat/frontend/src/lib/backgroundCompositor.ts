// WebGL2 compositor for the virtual background: the person (camera frame)
// over a blurred copy of the frame or over a background image, weighted by
// the segmenter's confidence mask.

export type BackgroundMode = "blur" | "image";

export type CompositorMask = {
	data: Uint8Array;
	width: number;
	height: number;
};

export type BackgroundCompositor = {
	render(
		frame: TexImageSource | VideoFrame,
		mask: CompositorMask,
		mode: BackgroundMode,
	): void;
	close(): void;
};

// One full-screen triangle from gl_VertexID; uv's y is flipped because
// texImage2D puts the image's top row at v = 0.
export const VERTEX_SHADER = `#version 300 es
out vec2 uv;
void main() {
	vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
	uv = vec2(p.x, 1.0 - p.y);
	gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

// Blur: the centre plus two rings of 6 taps (inner at half radius, outer
// rotated 30 degrees), 13 samples in one pass.
export const FRAGMENT_SHADER = `#version 300 es
precision mediump float;
in vec2 uv;
uniform sampler2D frame;
uniform sampler2D mask;
uniform sampler2D background;
uniform int mode;
uniform vec2 bgScale;
uniform vec2 blurRadius;
out vec4 color;
const vec2 TAPS[12] = vec2[](
	vec2(0.5, 0.0), vec2(0.25, 0.433), vec2(-0.25, 0.433),
	vec2(-0.5, 0.0), vec2(-0.25, -0.433), vec2(0.25, -0.433),
	vec2(0.866, 0.5), vec2(0.0, 1.0), vec2(-0.866, 0.5),
	vec2(-0.866, -0.5), vec2(0.0, -1.0), vec2(0.866, -0.5));
vec3 blurred() {
	vec3 sum = texture(frame, uv).rgb;
	for (int i = 0; i < 12; i++) sum += texture(frame, uv + TAPS[i] * blurRadius).rgb;
	return sum / 13.0;
}
void main() {
	vec3 person = texture(frame, uv).rgb;
	vec3 bg = mode == 0 ? blurred() : texture(background, (uv - 0.5) * bgScale + 0.5).rgb;
	color = vec4(mix(bg, person, smoothstep(0.35, 0.65, texture(mask, uv).r)), 1.0);
}`;

/** The shader's `mode` uniform: 0 blur, 1 image. */
export function modeUniform(mode: BackgroundMode): number {
	return mode === "blur" ? 0 : 1;
}

/** uv scale around the centre so a srcW x srcH image covers dstW x dstH. */
export function coverScale(
	srcW: number,
	srcH: number,
	dstW: number,
	dstH: number,
): [number, number] {
	const s = Math.max(dstW / srcW, dstH / srcH);
	return [dstW / (srcW * s), dstH / (srcH * s)];
}

/** Blur radius as a fraction of the frame's shorter side. */
const BLUR_FRACTION = 0.03;

function sizeOf(src: TexImageSource): [number, number] {
	if ("displayWidth" in src) return [src.displayWidth, src.displayHeight];
	if ("videoWidth" in src) return [src.videoWidth, src.videoHeight];
	if ("naturalWidth" in src) return [src.naturalWidth, src.naturalHeight];
	return [src.width, src.height];
}

function compile(gl: WebGL2RenderingContext): WebGLProgram {
	const prog = gl.createProgram();
	for (const [type, src] of [
		[gl.VERTEX_SHADER, VERTEX_SHADER],
		[gl.FRAGMENT_SHADER, FRAGMENT_SHADER],
	] as const) {
		const sh = gl.createShader(type) as WebGLShader;
		gl.shaderSource(sh, src);
		gl.compileShader(sh);
		gl.attachShader(prog, sh);
		gl.deleteShader(sh);
	}
	gl.linkProgram(prog);
	if (!gl.getProgramParameter(prog, gl.LINK_STATUS))
		throw new Error(`compositor link: ${gl.getProgramInfoLog(prog)}`);
	return prog;
}

function texture(gl: WebGL2RenderingContext, unit: number): WebGLTexture {
	const tex = gl.createTexture();
	gl.activeTexture(gl.TEXTURE0 + unit);
	gl.bindTexture(gl.TEXTURE_2D, tex);
	gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
	gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
	gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
	gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
	return tex;
}

function uploadRgba(
	gl: WebGL2RenderingContext,
	unit: number,
	src: TexImageSource,
) {
	gl.activeTexture(gl.TEXTURE0 + unit);
	gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, src);
}

function uploadMask(gl: WebGL2RenderingContext, m: CompositorMask) {
	gl.activeTexture(gl.TEXTURE1);
	gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
	gl.texImage2D(
		gl.TEXTURE_2D,
		0,
		gl.R8,
		m.width,
		m.height,
		0,
		gl.RED,
		gl.UNSIGNED_BYTE,
		m.data,
	);
}

export function createBackgroundCompositor(
	canvas: OffscreenCanvas | HTMLCanvasElement,
	background: TexImageSource,
): BackgroundCompositor {
	const gl = (canvas as HTMLCanvasElement).getContext("webgl2");
	if (!gl) throw new Error("WebGL2 unavailable");
	const prog = compile(gl);
	// biome-ignore lint/correctness/useHookAtTopLevel: WebGL call, not a React hook
	gl.useProgram(prog);
	const texs = [0, 1, 2].map((unit) => texture(gl, unit));
	uploadRgba(gl, 2, background);
	const u = (name: string) => gl.getUniformLocation(prog, name);
	for (const [i, n] of ["frame", "mask", "background"].entries())
		gl.uniform1i(u(n), i);
	const [bgW, bgH] = sizeOf(background);
	return {
		render(frame, mask, mode) {
			const [w, h] = sizeOf(frame);
			if (canvas.width !== w || canvas.height !== h)
				[canvas.width, canvas.height] = [w, h];
			gl.viewport(0, 0, w, h);
			uploadRgba(gl, 0, frame);
			uploadMask(gl, mask);
			const r = BLUR_FRACTION * Math.min(w, h);
			gl.uniform1i(u("mode"), modeUniform(mode));
			gl.uniform2fv(u("bgScale"), coverScale(bgW, bgH, w, h));
			gl.uniform2f(u("blurRadius"), r / w, r / h);
			gl.drawArrays(gl.TRIANGLES, 0, 3);
		},
		close() {
			for (const t of texs) gl.deleteTexture(t);
			gl.deleteProgram(prog);
		},
	};
}
