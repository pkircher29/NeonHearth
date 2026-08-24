// The only file that touches a real WebGL context. HomeTwin3D.svelte talks to
// it through the narrow TwinRenderer interface so component tests in jsdom can
// mock this module and never need a GPU.
import { WebGLRenderer, type Camera, type Scene } from 'three';

export interface TwinRenderer {
  setSize(width: number, height: number): void;
  setPixelRatio(ratio: number): void;
  render(scene: Scene, camera: Camera): void;
  dispose(): void;
}

/** True when the environment can hand out a WebGL (or WebGL2) context. */
export function detectWebGL(): boolean {
  try {
    if (typeof document === 'undefined') return false;
    const canvas = document.createElement('canvas');
    return Boolean(canvas.getContext('webgl2') ?? canvas.getContext('webgl'));
  } catch {
    return false;
  }
}

/** Creates the real renderer; returns null instead of throwing on failure. */
export function createTwinRenderer(canvas: HTMLCanvasElement): TwinRenderer | null {
  try {
    return new WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch {
    return null;
  }
}
