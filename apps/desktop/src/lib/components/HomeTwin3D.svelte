<script lang="ts">
  import { onMount, untrack, type Snippet } from 'svelte';
  import * as THREE from 'three';
  import type { PresenceState } from '../api/types';
  import {
    buildSceneDescription,
    SLAB_THICKNESS_M,
    type DevicePin,
    type HomePlan,
    type Placement,
    type SceneDescription,
    type TwinDevice
  } from '../twin/geometry';
  import { heatColor, riskBadge, riskFromPresence } from '../twin/heat';
  import { createTwinRenderer, detectWebGL, type TwinRenderer } from '../twin/webgl';

  interface Props {
    plan?: HomePlan | null;
    placements?: Placement[];
    devices?: TwinDevice[];
    presence?: Record<string, PresenceState>;
    bandwidth?: Record<string, number>;
    reducedMotion?: boolean;
    onselect?: (device_id: string) => void;
    onfallback?: () => void;
    fallback?: Snippet;
  }
  let {
    plan = null,
    placements = [],
    devices = [],
    presence = {},
    bandwidth = {},
    reducedMotion = false,
    onselect,
    onfallback,
    fallback
  }: Props = $props();

  let mode = $state<'pending' | '3d' | 'fallback'>('pending');
  let selected = $state<string | null>(null);
  let wallsHidden = $state(false);
  let isolatedFloorId = $state<string | null>(null);
  let prefersReduced = $state(false);
  const reduced = $derived(reducedMotion || prefersReduced);

  const sceneDesc = $derived<SceneDescription>(
    plan ? buildSceneDescription(plan, placements, devices) : { floors: [], bounds: null }
  );
  const allPins = $derived<DevicePin[]>(sceneDesc.floors.flatMap((floor) => floor.pins));

  // --- three.js plumbing (plain, non-reactive; effects gate on `mode`) -----
  let stage = $state<HTMLDivElement | null>(null);
  let canvas = $state<HTMLCanvasElement | null>(null);
  let renderer: TwinRenderer | null = null;
  let scene: THREE.Scene | null = null;
  let camera: THREE.PerspectiveCamera | null = null;
  let staticRoot: THREE.Group | null = null;
  let floorNodes = new Map<string, { group: THREE.Group; walls: THREE.Group }>();
  let pinNodes = new Map<string, { pin: THREE.Mesh; ring: THREE.Mesh }>();
  const prevPresence = new Map<string, PresenceState>();
  const pulses = new Map<string, number>();

  // Orbit state: spherical coordinates around a target point.
  const target = new THREE.Vector3(0, 1, 0);
  let theta = -Math.PI / 4;
  let phi = 1.05;
  let radius = 14;
  let focusFrom: THREE.Vector3 | null = null;
  let focusTo: THREE.Vector3 | null = null;
  let focusStart = 0;
  let rafHandle = 0;
  let dragging: 'orbit' | 'pan' | null = null;
  let dragMoved = 0;
  let lastPointer = { x: 0, y: 0 };

  function applyCamera() {
    if (!camera) return;
    camera.position.set(
      target.x + radius * Math.sin(phi) * Math.cos(theta),
      target.y + radius * Math.cos(phi),
      target.z + radius * Math.sin(phi) * Math.sin(theta)
    );
    camera.lookAt(target);
  }

  function renderFrame() {
    if (renderer && scene && camera) renderer.render(scene, camera);
  }

  function requestRender() {
    // In reduced motion there is no loop; changes render exactly once.
    if (reduced || mode !== '3d') {
      applyCamera();
      renderFrame();
    }
  }

  function stopLoop() {
    if (rafHandle) cancelAnimationFrame(rafHandle);
    rafHandle = 0;
  }

  function startLoop() {
    stopLoop();
    const tick = (now: number) => {
      stepAnimations(now);
      applyCamera();
      renderFrame();
      rafHandle = requestAnimationFrame(tick);
    };
    rafHandle = requestAnimationFrame(tick);
  }

  function stepAnimations(now: number) {
    for (const [id, start] of pulses) {
      const k = (now - start) / 600;
      const node = pinNodes.get(id);
      if (!node) {
        pulses.delete(id);
        continue;
      }
      if (k >= 1) {
        pulses.delete(id);
        node.pin.scale.setScalar(selected === id ? 1.35 : 1);
      } else {
        node.pin.scale.setScalar((selected === id ? 1.35 : 1) * (1 + 0.35 * Math.sin(Math.PI * k)));
      }
    }
    if (focusFrom && focusTo) {
      const k = Math.min(1, (now - focusStart) / 500);
      target.copy(focusFrom).lerp(focusTo, k * (2 - k));
      if (k >= 1) {
        focusFrom = null;
        focusTo = null;
      }
    }
  }

  function resetView() {
    const bounds = sceneDesc.bounds;
    focusFrom = null;
    focusTo = null;
    theta = -Math.PI / 4;
    phi = 1.05;
    if (bounds) {
      const mid = sceneDesc.floors.length
        ? (Math.min(...sceneDesc.floors.map((f) => f.elevation_m))
            + Math.max(...sceneDesc.floors.map((f) => f.elevation_m + f.ceiling_m))) / 2
        : 1;
      target.set(bounds.center.x, mid, bounds.center.y);
      radius = bounds.radius_m * 2.4;
    } else {
      target.set(0, 1, 0);
      radius = 14;
    }
    requestRender();
  }

  function focusOn(pin: DevicePin) {
    const floor = sceneDesc.floors.find((f) => f.floor_id === pin.floor_id);
    const destination = new THREE.Vector3(
      pin.position.x,
      (floor?.elevation_m ?? 0) + pin.height_m,
      pin.position.y
    );
    if (reduced) {
      target.copy(destination);
      radius = Math.min(radius, 6);
      requestRender();
    } else {
      focusFrom = target.clone();
      focusTo = destination;
      focusStart = performance.now();
      radius = Math.min(radius, 6);
    }
  }

  function select(device_id: string) {
    selected = device_id;
    onselect?.(device_id);
    const pin = allPins.find((candidate) => candidate.device_id === device_id);
    if (pin && mode === '3d') focusOn(pin);
  }

  // --- Pointer / wheel / keyboard controls ---------------------------------
  function onPointerDown(event: PointerEvent) {
    dragging = event.button === 2 || event.shiftKey ? 'pan' : 'orbit';
    dragMoved = 0;
    lastPointer = { x: event.clientX, y: event.clientY };
    (event.currentTarget as HTMLElement | null)?.setPointerCapture?.(event.pointerId);
  }

  function onPointerMove(event: PointerEvent) {
    if (!dragging) return;
    const dx = event.clientX - lastPointer.x;
    const dy = event.clientY - lastPointer.y;
    lastPointer = { x: event.clientX, y: event.clientY };
    dragMoved += Math.abs(dx) + Math.abs(dy);
    if (dragging === 'orbit') {
      theta -= dx * 0.005;
      phi = Math.min(1.5, Math.max(0.15, phi - dy * 0.005));
    } else if (camera) {
      const pace = radius * 0.0016;
      const right = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 0);
      const forward = new THREE.Vector3(-Math.cos(theta), 0, -Math.sin(theta));
      target.addScaledVector(right, -dx * pace);
      target.addScaledVector(forward, -dy * pace);
    }
    requestRender();
  }

  function onPointerUp(event: PointerEvent) {
    const wasDrag = dragMoved > 5;
    dragging = null;
    if (!wasDrag) pickAt(event);
  }

  function onWheel(event: WheelEvent) {
    event.preventDefault();
    radius = Math.min(200, Math.max(1.5, radius * (1 + event.deltaY * 0.001)));
    requestRender();
  }

  function onKeyDown(event: KeyboardEvent) {
    const step = 0.15;
    if (event.key === 'ArrowLeft') theta -= step;
    else if (event.key === 'ArrowRight') theta += step;
    else if (event.key === 'ArrowUp') phi = Math.max(0.15, phi - step);
    else if (event.key === 'ArrowDown') phi = Math.min(1.5, phi + step);
    else if (event.key === '+' || event.key === '=') radius = Math.max(1.5, radius * 0.9);
    else if (event.key === '-') radius = Math.min(200, radius * 1.1);
    else return;
    event.preventDefault();
    requestRender();
  }

  function pickAt(event: PointerEvent) {
    if (!camera || !canvas || pinNodes.size === 0) return;
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const pointer = new THREE.Vector2(
      ((event.clientX - rect.left) / rect.width) * 2 - 1,
      -((event.clientY - rect.top) / rect.height) * 2 + 1
    );
    const raycaster = new THREE.Raycaster();
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects([...pinNodes.values()].map((node) => node.pin), false);
    const hit = hits.find((candidate) => typeof candidate.object.userData.device_id === 'string');
    if (hit) select(hit.object.userData.device_id as string);
  }

  // --- Scene assembly from the pure description ----------------------------
  function disposeObject(object: THREE.Object3D) {
    object.traverse((child) => {
      const mesh = child as THREE.Mesh;
      if (mesh.geometry) mesh.geometry.dispose();
      const material = mesh.material as THREE.Material | THREE.Material[] | undefined;
      if (Array.isArray(material)) material.forEach((entry) => entry.dispose());
      else material?.dispose();
    });
  }

  function polygonMesh(polygon: { x: number; y: number }[], color: string, lift: number): THREE.Mesh {
    const shape = new THREE.Shape(polygon.map((point) => new THREE.Vector2(point.x, point.y)));
    const geometry = new THREE.ShapeGeometry(shape);
    geometry.rotateX(Math.PI / 2); // plan (x, y) -> three (x, z), lying flat
    const mesh = new THREE.Mesh(
      geometry,
      new THREE.MeshLambertMaterial({ color, side: THREE.DoubleSide })
    );
    mesh.position.y = lift;
    return mesh;
  }

  function rebuildStatic(desc: SceneDescription) {
    if (!scene) return;
    if (staticRoot) {
      scene.remove(staticRoot);
      disposeObject(staticRoot);
    }
    floorNodes = new Map();
    pinNodes = new Map();
    staticRoot = new THREE.Group();
    for (const floor of desc.floors) {
      const group = new THREE.Group();
      group.position.y = floor.elevation_m;
      const walls = new THREE.Group();
      for (const slab of floor.slabs) {
        group.add(polygonMesh(slab.polygon, slab.color, slab.kind === 'extent' ? -SLAB_THICKNESS_M / 2 : 0.01));
      }
      for (const box of floor.walls) {
        const mesh = new THREE.Mesh(
          new THREE.BoxGeometry(box.length_m, box.height_m, box.thickness_m),
          new THREE.MeshLambertMaterial({ color: box.color, transparent: true, opacity: 0.92 })
        );
        mesh.position.set(box.center.x, box.base_m + box.height_m / 2, box.center.y);
        mesh.rotation.y = -box.angle_rad;
        walls.add(mesh);
      }
      for (const stair of floor.stairs) {
        const mesh = new THREE.Mesh(
          new THREE.BoxGeometry(stair.length_m, 0.02, 0.4),
          new THREE.MeshBasicMaterial({ color: stair.color })
        );
        mesh.position.set(stair.center.x, 0.02, stair.center.y);
        mesh.rotation.y = -stair.angle_rad;
        group.add(mesh);
      }
      for (const pin of floor.pins) {
        const mesh = new THREE.Mesh(
          new THREE.SphereGeometry(0.14, 16, 12),
          // Neutral at build time; the live-state effect applies heat colors.
          new THREE.MeshBasicMaterial({ color: heatColor(null) })
        );
        mesh.position.set(pin.position.x, pin.height_m, pin.position.y);
        mesh.userData.device_id = pin.device_id;
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(0.2, 0.27, 24),
          new THREE.MeshBasicMaterial({ color: '#ffcd66', side: THREE.DoubleSide })
        );
        ring.geometry.rotateX(-Math.PI / 2);
        ring.position.set(pin.position.x, pin.height_m - 0.05, pin.position.y);
        ring.visible = false;
        group.add(mesh, ring);
        pinNodes.set(pin.device_id, { pin: mesh, ring });
      }
      for (const cone of floor.cones) {
        const coneRadius = Math.tan(cone.half_angle_rad) * cone.length_m;
        const geometry = new THREE.ConeGeometry(coneRadius, cone.length_m, 20, 1, true);
        geometry.rotateX(Math.PI); // apex toward local -y ... then re-center
        geometry.translate(0, cone.length_m / 2, 0); // apex at origin, base at +y
        const mesh = new THREE.Mesh(
          geometry,
          new THREE.MeshBasicMaterial({ color: '#63f3f0', transparent: true, opacity: 0.14, side: THREE.DoubleSide })
        );
        const direction = new THREE.Vector3(cone.direction.x, cone.direction.z, cone.direction.y);
        mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
        mesh.position.set(cone.apex.x, cone.apex.h, cone.apex.y);
        group.add(mesh);
      }
      group.add(walls);
      staticRoot.add(group);
      floorNodes.set(floor.floor_id, { group, walls });
    }
    scene.add(staticRoot);
    applyVisibility();
  }

  function applyVisibility() {
    for (const [floor_id, node] of floorNodes) {
      node.group.visible = isolatedFloorId === null || isolatedFloorId === floor_id;
      node.walls.visible = !wallsHidden;
    }
  }

  function updatePins(now: number) {
    for (const pin of allPins) {
      const node = pinNodes.get(pin.device_id);
      const state = presence[pin.device_id] ?? 'unknown';
      const previous = prevPresence.get(pin.device_id);
      if (previous !== undefined && previous !== state && !reduced) pulses.set(pin.device_id, now);
      prevPresence.set(pin.device_id, state);
      if (!node) continue;
      const material = node.pin.material as THREE.MeshBasicMaterial;
      material.color.set(heatColor(bandwidth[pin.device_id] ?? null));
      material.opacity = state === 'offline' || state === 'unknown' ? 0.55 : 1;
      material.transparent = material.opacity < 1;
      const badge = riskBadge(riskFromPresence(state));
      node.ring.visible = badge.ring;
      (node.ring.material as THREE.MeshBasicMaterial).color.set(badge.outline);
      if (!pulses.has(pin.device_id)) node.pin.scale.setScalar(selected === pin.device_id ? 1.35 : 1);
    }
  }

  function resize() {
    if (!renderer || !camera || !stage) return;
    const width = stage.clientWidth || 640;
    const height = stage.clientHeight || 420;
    renderer.setSize(width, height);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    requestRender();
  }

  onMount(() => {
    if (typeof window.matchMedia === 'function') {
      prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    if (!detectWebGL()) {
      mode = 'fallback';
      onfallback?.();
      return;
    }
    const targetCanvas = canvas;
    renderer = targetCanvas ? createTwinRenderer(targetCanvas) : null;
    if (!renderer) {
      mode = 'fallback';
      onfallback?.();
      return;
    }
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    scene = new THREE.Scene();
    scene.add(new THREE.AmbientLight('#9bb7bb', 1.1));
    const sun = new THREE.DirectionalLight('#e9fbfc', 1.4);
    sun.position.set(6, 12, 8);
    scene.add(sun);
    camera = new THREE.PerspectiveCamera(50, 4 / 3, 0.1, 500);
    mode = '3d';
    window.addEventListener('resize', resize);
    resize();
    resetView();
    return () => {
      stopLoop();
      window.removeEventListener('resize', resize);
      if (staticRoot) disposeObject(staticRoot);
      renderer?.dispose();
      renderer = null;
      scene = null;
      camera = null;
    };
  });

  $effect(() => {
    if (mode !== '3d') return;
    const desc = sceneDesc; // tracked read; the work below must not track more
    untrack(() => {
      rebuildStatic(desc);
      prevPresence.clear();
      resetView();
    });
  });

  $effect(() => {
    if (mode !== '3d') return;
    void wallsHidden;
    void isolatedFloorId;
    applyVisibility();
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void presence;
    void bandwidth;
    void selected;
    updatePins(typeof performance !== 'undefined' ? performance.now() : 0);
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    if (reduced) {
      stopLoop();
      requestRender();
    } else {
      startLoop();
    }
    return () => stopLoop();
  });
</script>

<section
  class="twin"
  data-mode={mode}
  data-reduced-motion={String(reduced)}
  data-floor-count={sceneDesc.floors.length}
  data-pin-count={allPins.length}
  data-selected={selected ?? ''}
  aria-label="3D home twin"
>
  {#if mode === '3d'}
    <div class="twin-toolbar" role="toolbar" aria-label="3D view controls">
      <button type="button" onclick={resetView}>Reset view</button>
      <button
        type="button"
        aria-pressed={wallsHidden}
        onclick={() => { wallsHidden = !wallsHidden; }}
      >{wallsHidden ? 'Show walls' : 'Hide walls'}</button>
      <button
        type="button"
        aria-pressed={isolatedFloorId === null}
        onclick={() => { isolatedFloorId = null; }}
      >All floors</button>
      {#each sceneDesc.floors as floor (floor.floor_id)}
        <button
          type="button"
          aria-pressed={isolatedFloorId === floor.floor_id}
          onclick={() => { isolatedFloorId = isolatedFloorId === floor.floor_id ? null : floor.floor_id; }}
        >{floor.name}</button>
      {/each}
    </div>
  {/if}
  <!-- The stage is a genuine custom widget (role="application" with full
       keyboard support); svelte's static a11y rules cannot see that. -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
  <div
    class="twin-stage"
    class:stage-hidden={mode !== '3d'}
    role="application"
    aria-label="Home model. Drag to orbit, shift-drag to pan, scroll to zoom, arrow keys to rotate."
    tabindex={mode === '3d' ? 0 : -1}
    bind:this={stage}
    onpointerdown={onPointerDown}
    onpointermove={onPointerMove}
    onpointerup={onPointerUp}
    onwheel={onWheel}
    onkeydown={onKeyDown}
  >
    <canvas bind:this={canvas}></canvas>
  </div>
  {#if mode === 'fallback'}
    <div class="twin-fallback" role="status">
      {#if fallback}{@render fallback()}{:else}
        <span aria-hidden="true">◌</span>
        <strong>3D view is unavailable on this device</strong>
        <p>WebGL could not start. The 2D floor plan shows the same devices and placements.</p>
      {/if}
    </div>
  {/if}
  <div class="twin-devices">
    <h2 class="visually-hidden" id="twin-device-list-heading">Devices placed in this home</h2>
    <ul class="visually-hidden" aria-labelledby="twin-device-list-heading">
      {#each allPins as pin (pin.device_id)}
        <li>
          <button
            type="button"
            data-device-id={pin.device_id}
            aria-pressed={selected === pin.device_id}
            onclick={() => select(pin.device_id)}
          >{pin.label} — {presence[pin.device_id] ?? 'unknown'}</button>
        </li>
      {/each}
    </ul>
  </div>
</section>

<style>
  .twin { position: relative; display: grid; gap: 10px; }
  .twin-toolbar { display: flex; flex-wrap: wrap; gap: 8px; }
  .twin-toolbar button { border: 1px solid var(--line); border-radius: 8px; color: var(--ink); background: var(--panel); min-height: 36px; padding: 0 12px; cursor: pointer; font: 500 12.5px var(--font-body); }
  .twin-toolbar button[aria-pressed='true'] { border-color: var(--ember); color: var(--ember); }
  .twin-stage { min-height: 320px; border: 1px solid var(--line); border-radius: var(--radius-card); background: var(--ground); overflow: hidden; touch-action: none; }
  .twin-stage:focus-visible { outline: 2px solid var(--ember); outline-offset: 2px; }
  .twin-stage.stage-hidden { display: none; }
  .twin-stage canvas { display: block; width: 100%; height: 100%; }
  .twin-fallback { border: 1px dashed var(--line); border-radius: var(--radius-card); padding: 18px; color: var(--ink-mute); display: grid; gap: 6px; justify-items: start; }
  .twin-fallback strong { color: var(--ink); }
  .twin-fallback p { margin: 0; font-size: 12px; line-height: 1.5; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
</style>
