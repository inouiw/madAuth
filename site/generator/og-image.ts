import { Resvg } from '@resvg/resvg-js';
import satori from 'satori';

/**
 * The link-preview image of a blog page (og:image): a 1200×630 card with the page's title, drawn at build time.
 * satori lays the card out and turns its text into SVG paths, resvg turns the SVG into a PNG.
 */

export const OG_WIDTH = 1200;
export const OG_HEIGHT = 630;

export interface OgCard {
  /** Above the title, e.g. "Blog". */
  kicker: string;
  title: string;
  /** Below the title, e.g. the author and the date; empty for none. */
  byline: string;
}

/** Public Sans, regular and bold, as WOFF (satori reads TTF, OTF and WOFF, not WOFF2). */
export interface OgFonts {
  regular: Buffer;
  bold: Buffer;
}

interface Node {
  type: 'div';
  props: { style: Record<string, string | number>; children?: string | Node | Node[] };
}

const div = (style: Node['props']['style'], children?: Node['props']['children']): Node => ({
  type: 'div',
  props: { style, children },
});

const INK = '#f1f2f3';
const MUTED = '#a7aab0';

const BORDER = 12;
const PADDING_X = 80;
const PADDING_Y = 64;

function cardNode(card: OgCard): Node {
  // Long titles (three lines and more) get a smaller size, so they fit between the kicker and the byline.
  const titleSize = card.title.length > 100 ? 50 : card.title.length > 70 ? 58 : 66;
  // Fixed sizes rather than padding: satori counts padding outside a width of 100%.
  return div(
    {
      width: OG_WIDTH,
      height: OG_HEIGHT,
      display: 'flex',
      flexDirection: 'column',
      background: '#101113',
      borderTop: `${BORDER}px solid ${INK}`,
      color: INK,
      fontFamily: 'Public Sans',
    },
    div(
      {
        width: OG_WIDTH - 2 * PADDING_X,
        height: OG_HEIGHT - BORDER - 2 * PADDING_Y,
        margin: `${PADDING_Y}px ${PADDING_X}px`,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
      },
      [
        div({ display: 'flex', fontSize: 34, color: MUTED }, [
          div({ fontWeight: 700, color: INK }, 'madAuth'),
          div({ marginLeft: 14 }, `· ${card.kicker}`),
        ]),
        div({ display: 'flex', fontSize: titleSize, fontWeight: 700, lineHeight: 1.15, letterSpacing: -1 }, card.title),
        div({ display: 'flex', justifyContent: 'space-between', fontSize: 30, color: MUTED }, [
          div({}, card.byline),
          div({ fontWeight: 700, color: INK }, 'madauth.com'),
        ]),
      ],
    ),
  );
}

/** The card as a PNG. */
export async function renderOgImage(card: OgCard, fonts: OgFonts): Promise<Buffer> {
  const svg = await satori(cardNode(card) as unknown as Parameters<typeof satori>[0], {
    width: OG_WIDTH,
    height: OG_HEIGHT,
    fonts: [
      { name: 'Public Sans', data: fonts.regular, weight: 400, style: 'normal' },
      { name: 'Public Sans', data: fonts.bold, weight: 700, style: 'normal' },
    ],
  });
  return new Resvg(svg, { fitTo: { mode: 'width', value: OG_WIDTH } }).render().asPng();
}
