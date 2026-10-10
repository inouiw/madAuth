// The QR code of the authenticator app's key, drawn as an SVG so it fits any theme and needs no image.
import { encode } from 'uqr';

/** Light modules around the code, as the QR standard asks for. */
const QUIET_ZONE = 4;

export interface QrModules {
  /** Modules per side, without the quiet zone. */
  size: number;
  /** An SVG path of the dark modules, one unit per module, the top-left module at 0 0. */
  d: string;
}

/** The QR code for `text`, as a path to draw in a template. */
export function qrModules(text: string): QrModules {
  // No border: the quiet zone comes from the viewBox. `data[y][x]` is true for a dark module.
  const { size, data } = encode(text, { ecc: 'M', border: 0 });
  let d = '';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) if (data[y][x]) d += `M${x} ${y}h1v1h-1z`;
  }
  return { size, d };
}

/** The `viewBox` that shows a code of `size` modules with its quiet zone. */
export function qrViewBox(size: number): string {
  return `${-QUIET_ZONE} ${-QUIET_ZONE} ${size + 2 * QUIET_ZONE} ${size + 2 * QUIET_ZONE}`;
}

/** The QR code for `text` as an SVG: dark modules in `currentColor`, no background, sized by CSS. */
export function qrSvg(text: string): string {
  const { size, d } = qrModules(text);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${qrViewBox(size)}" shape-rendering="crispEdges" role="img"><path d="${d}" fill="currentColor"/></svg>`;
}
