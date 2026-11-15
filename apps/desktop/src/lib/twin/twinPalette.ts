// Scene colours read from the app's design tokens so the twin follows the
// theme instead of hardcoding hex values. Fallbacks equal the current token
// values and apply in tests / before styles load.

export interface TwinPalette {
  stage: string; // canvas background (--bg)
  ink: string; // brightest neutral (--ink): wall caps, pin stems
  surface: string; // dark glass (--surface)
  raised: string; // room slab tint (--surface-raised)
  ground: string; // hemisphere bounce colour (--line)
  ambient: string; // cool ambient (--muted-strong)
  key: string; // warm key light (--gold)
  fill: string; // cool fill (--accent)
  highlight: string; // hovered / selected room (--accent)
  risk: string; // flat alert colour, never the heat ramp (--risk)
}

const FALLBACK: TwinPalette = {
  stage: '#061019',
  ink: '#e9fbfc',
  surface: '#0b1c26',
  raised: '#102a35',
  ground: '#17323d',
  ambient: '#9bb7bb',
  key: '#ffcd66',
  fill: '#63f3f0',
  highlight: '#63f3f0',
  risk: '#ff5c9b'
};

function token(style: CSSStyleDeclaration | null, name: string, fallback: string): string {
  const value = style?.getPropertyValue(name).trim();
  return value && value.length > 0 ? value : fallback;
}

export function readTwinPalette(root: Element | null = typeof document !== 'undefined' ? document.documentElement : null): TwinPalette {
  let style: CSSStyleDeclaration | null = null;
  try {
    style = root && typeof getComputedStyle === 'function' ? getComputedStyle(root) : null;
  } catch {
    style = null;
  }
  return {
    stage: token(style, '--bg', FALLBACK.stage),
    ink: token(style, '--ink', FALLBACK.ink),
    surface: token(style, '--surface', FALLBACK.surface),
    raised: token(style, '--surface-raised', FALLBACK.raised),
    ground: token(style, '--line', FALLBACK.ground),
    ambient: token(style, '--muted-strong', FALLBACK.ambient),
    key: token(style, '--gold', FALLBACK.key),
    fill: token(style, '--accent', FALLBACK.fill),
    highlight: token(style, '--accent', FALLBACK.highlight),
    risk: token(style, '--risk', FALLBACK.risk)
  };
}
