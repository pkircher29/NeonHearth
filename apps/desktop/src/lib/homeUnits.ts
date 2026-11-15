/** The wire format and 3D geometry stay in meters; units are a display preference. */
export type HomeUnits = 'metric' | 'imperial';
export const METERS_PER_FOOT = 0.3048;
export const unitSymbol = (units: HomeUnits) => units === 'imperial' ? 'ft' : 'm';
export const toDisplayLength = (meters: number, units: HomeUnits) => meters / (units === 'imperial' ? METERS_PER_FOOT : 1);
export const fromDisplayLength = (value: number, units: HomeUnits) => value * (units === 'imperial' ? METERS_PER_FOOT : 1);
export const gridStep = (units: HomeUnits) => units === 'imperial' ? 0.0254 : 0.1;
export const formatLength = (meters: number, units: HomeUnits) => `${toDisplayLength(meters, units).toFixed(2)} ${unitSymbol(units)}`;
export const SQUARE_FEET_PER_SQUARE_METER = 1 / (METERS_PER_FOOT * METERS_PER_FOOT);
/** Area in the display unit: m² or ft². */
export const formatArea = (squareMeters: number, units: HomeUnits) =>
  units === 'imperial' ? `${(squareMeters * SQUARE_FEET_PER_SQUARE_METER).toFixed(0)} ft²` : `${squareMeters.toFixed(1)} m²`;
export function readHomeUnits(): HomeUnits {
  try { return localStorage.getItem('neonhearth.home.units') === 'imperial' ? 'imperial' : 'metric'; }
  catch { return 'metric'; }
}
export function saveHomeUnits(units: HomeUnits) {
  try { localStorage.setItem('neonhearth.home.units', units); } catch { /* Preference storage is optional. */ }
}
