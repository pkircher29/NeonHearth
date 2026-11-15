// Pure camera maths for the 3D home twin (home tools v2 · spec E).
//
// Poses are orbit-style: a spherical offset (theta around +y, phi from +y,
// radius) around a target, in three.js world space (plan x -> x, plan y -> z,
// vertical -> y). No three.js import: the component owns the camera object,
// this file only decides where it should be and how it gets there.

import type { SceneDescription, Vec2 } from './geometry';

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}
export interface CameraPose {
  theta: number;
  phi: number;
  radius: number;
  target: Vec3;
}
export type CameraPresetName = 'top' | 'iso' | 'front';

export const CAMERA_FOV_DEG = 50;
/** Orbit limits shared by pointer, keyboard, and presets. */
export const PHI_MIN = 0.02;
export const PHI_MAX = 1.55;
export const RADIUS_MIN = 1.5;
export const RADIUS_MAX = 200;
export const TRANSITION_MS = 450;
export const FRAME_MARGIN = 1.12;
/** Extra vertical air between storeys so a lower floor's interior stays visible (exploded stack). */
export const EXPLODE_GAP_M = 1.2;
/** Height of a cut-away wall stub (the dollhouse cut). */
export const WALL_STUB_M = 0.25;

export interface SceneBox {
  min: Vec3;
  max: Vec3;
}

/** World-space box of the whole model (all floors stacked), or null when empty. */
export function sceneBox(scene: SceneDescription, explode = 0): SceneBox | null {
  if (!scene.bounds || scene.floors.length === 0) return null;
  let low = Infinity;
  let high = -Infinity;
  scene.floors.forEach((floor, index) => {
    const lift = index * explode;
    if (floor.elevation_m + lift < low) low = floor.elevation_m + lift;
    if (floor.elevation_m + floor.ceiling_m + lift > high) high = floor.elevation_m + floor.ceiling_m + lift;
  });
  return {
    min: { x: scene.bounds.min.x, y: low, z: scene.bounds.min.y },
    max: { x: scene.bounds.max.x, y: high, z: scene.bounds.max.y }
  };
}

const halfTan = (fovDeg: number) => Math.tan((fovDeg * Math.PI) / 360);
const centerOf = (box: SceneBox): Vec3 => ({
  x: (box.min.x + box.max.x) / 2,
  y: (box.min.y + box.max.y) / 2,
  z: (box.min.z + box.max.z) / 2
});

/** Distance at which a (width x height) rectangle fits the view with margin. */
export function fitDistance(width: number, height: number, fovDeg: number, aspect: number): number {
  const t = halfTan(fovDeg);
  const safeAspect = aspect > 0.01 ? aspect : 1;
  return Math.max(height / 2 / t, width / 2 / (t * safeAspect)) * FRAME_MARGIN;
}

export const DEFAULT_POSE: CameraPose = {
  theta: -Math.PI / 4,
  phi: 1.05,
  radius: 14,
  target: { x: 0, y: 1, z: 0 }
};

/**
 * Pose for one of the three presets. Isometric is the default and keeps the
 * long-standing framing (radius = 2.4 x bounds radius); Top looks straight
 * down with plan +x to the right and plan +y down the screen; Front looks
 * horizontally from the plan's +y side so floors read as a stack.
 */
export function presetPose(
  name: CameraPresetName,
  scene: SceneDescription,
  aspect = 4 / 3,
  fovDeg = CAMERA_FOV_DEG,
  explode = 0
): CameraPose {
  const box = sceneBox(scene, explode);
  if (!box || !scene.bounds) return { ...DEFAULT_POSE, target: { ...DEFAULT_POSE.target } };
  const target = centerOf(box);
  const width = box.max.x - box.min.x;
  const depth = box.max.z - box.min.z;
  const height = box.max.y - box.min.y;
  if (name === 'iso') {
    return { theta: -Math.PI / 4, phi: 1.05, radius: Math.max(scene.bounds.radius_m, height) * 2.4, target };
  }
  if (name === 'top') {
    return {
      theta: Math.PI / 2,
      phi: PHI_MIN,
      radius: fitDistance(width, depth, fovDeg, aspect) + height / 2,
      target
    };
  }
  return {
    theta: Math.PI / 2,
    phi: 1.5,
    radius: fitDistance(width, height, fovDeg, aspect) + depth / 2,
    target
  };
}

/** A pose that frames a world-space box from the current viewing angles. */
export function framePose(
  box: SceneBox,
  current: Pick<CameraPose, 'theta' | 'phi'>,
  aspect = 4 / 3,
  fovDeg = CAMERA_FOV_DEG,
  minRadius = 3
): CameraPose {
  const target = centerOf(box);
  const diagonal = Math.hypot(box.max.x - box.min.x, box.max.y - box.min.y, box.max.z - box.min.z);
  const t = halfTan(fovDeg);
  const safeAspect = aspect > 0.01 ? aspect : 1;
  const radius = (diagonal / 2 / Math.min(t, t * safeAspect)) * FRAME_MARGIN * 0.8;
  return {
    theta: current.theta,
    phi: current.phi,
    radius: Math.min(RADIUS_MAX, Math.max(minRadius, radius)),
    target
  };
}

/** World box around a point (a pin) or a plan polygon on a floor. */
export function boxAround(points: Vec3[], pad = 0.4): SceneBox {
  const box: SceneBox = {
    min: { x: Infinity, y: Infinity, z: Infinity },
    max: { x: -Infinity, y: -Infinity, z: -Infinity }
  };
  for (const p of points) {
    box.min.x = Math.min(box.min.x, p.x); box.max.x = Math.max(box.max.x, p.x);
    box.min.y = Math.min(box.min.y, p.y); box.max.y = Math.max(box.max.y, p.y);
    box.min.z = Math.min(box.min.z, p.z); box.max.z = Math.max(box.max.z, p.z);
  }
  box.min.x -= pad; box.min.y -= pad; box.min.z -= pad;
  box.max.x += pad; box.max.y += pad; box.max.z += pad;
  return box;
}

/** Shortest signed angular distance from a to b, in (-PI, PI]. */
export function angleDelta(from: number, to: number): number {
  let delta = (to - from) % (Math.PI * 2);
  if (delta > Math.PI) delta -= Math.PI * 2;
  else if (delta <= -Math.PI) delta += Math.PI * 2;
  return delta;
}

export function easeOut(k: number): number {
  const clamped = Math.min(1, Math.max(0, k));
  return clamped * (2 - clamped);
}

/** Interpolates two poses; theta takes the short way around. */
export function lerpPose(from: CameraPose, to: CameraPose, k: number): CameraPose {
  return {
    theta: from.theta + angleDelta(from.theta, to.theta) * k,
    phi: from.phi + (to.phi - from.phi) * k,
    radius: from.radius + (to.radius - from.radius) * k,
    target: {
      x: from.target.x + (to.target.x - from.target.x) * k,
      y: from.target.y + (to.target.y - from.target.y) * k,
      z: from.target.z + (to.target.z - from.target.z) * k
    }
  };
}

/** Eased tween progress at time `now`; done when k reaches 1. */
export function tweenProgress(start: number, now: number, duration = TRANSITION_MS): { k: number; done: boolean } {
  const raw = duration <= 0 ? 1 : (now - start) / duration;
  const k = Math.min(1, Math.max(0, raw));
  return { k: easeOut(k), done: k >= 1 };
}

/**
 * Dollhouse cut: true when a wall sits on the camera's side of the model, so it
 * should render as a short stub and let the eye see in over it. Boolean on
 * purpose (same camera, same pixels). Never cuts from near-overhead views,
 * where walls hide nothing.
 */
export function wallIsCut(
  wallMid: Vec2,
  modelCenter: Vec2,
  toCamera: Vec2,
  phi: number,
  margin = 0.4
): boolean {
  const norm = Math.hypot(toCamera.x, toCamera.y);
  if (norm < 1e-9 || Math.sin(phi) < 0.45) return false;
  const along = ((wallMid.x - modelCenter.x) * toCamera.x + (wallMid.y - modelCenter.y) * toCamera.y) / norm;
  return along > margin;
}

/** Stub geometry for a wall box: new base-relative height, or null when the box hides entirely. */
export function stubbedBox(base_m: number, height_m: number, stub = WALL_STUB_M): { base: number; height: number } | null {
  if (base_m >= stub) return null;
  return { base: base_m, height: Math.min(base_m + height_m, stub) - base_m };
}

/** Contact-shadow blob under a pin: higher pins cast a wider, fainter shadow. */
export function contactShadow(height_m: number): { radius: number; opacity: number } {
  const h = Math.min(Math.max(height_m, 0), 4);
  return { radius: 0.28 + 0.1 * h, opacity: Math.max(0.18, 0.62 - 0.11 * h) };
}

/** Deterministic 0..1 hash for per-wall material variation. */
export function unitHash(id: string): number {
  let h = 2166136261;
  for (let i = 0; i < id.length; i += 1) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

/** Wall roughness in a gentle band so neighbouring walls differ a little. */
export function wallRoughness(id: string): number {
  return 0.62 + unitHash(id) * 0.26;
}
