<script lang="ts">
  import { onMount, untrack, type Snippet } from 'svelte';
  import * as THREE from 'three';
  import type { PresenceState } from '../api/types';
  import {
    buildSceneDescription,
    SLAB_THICKNESS_M,
    triangulatePolygon,
    type DevicePin,
    type HomePlan,
    type Placement,
    type SceneDescription,
    type SlabDesc,
    type TwinDevice,
    type Vec2
  } from '../twin/geometry';
  import { HEAT_UNAVAILABLE_COLOR, heatColor, riskBadge, riskFromPresence } from '../twin/heat';
  import {
    boxAround,
    contactShadow,
    EXPLODE_GAP_M,
    stubbedBox,
    WALL_STUB_M,
    wallIsCut,
    framePose,
    lerpPose,
    PHI_MAX,
    PHI_MIN,
    presetPose,
    RADIUS_MAX,
    RADIUS_MIN,
    sceneBox,
    tweenProgress,
    wallRoughness,
    unitHash,
    type CameraPose,
    type CameraPresetName
  } from '../twin/twinCamera';
  import { buildPinCard, formatArea, type PinCard, type TwinDeviceInfo } from '../twin/twinCard';
  import { readTwinPalette, type TwinPalette } from '../twin/twinPalette';
  import { cullLabels, estimateLabelSize, labelAnchor, labelsVisibleForPhi, pinScreenScale, type LabelCandidate } from '../twin/twinLabels';
  import { createTwinRenderer, detectWebGL, type TwinRenderer } from '../twin/webgl';

  interface Props {
    plan?: HomePlan | null;
    placements?: Placement[];
    devices?: TwinDevice[];
    /** Evidence / last-seen per device for the detail card (kept apart from `devices` so live updates never rebuild the scene). */
    deviceInfo?: Record<string, TwinDeviceInfo>;
    presence?: Record<string, PresenceState>;
    bandwidth?: Record<string, number>;
    reducedMotion?: boolean;
    /** False while the hosting panel is hidden: the render loop stops (audit M-26). */
    visible?: boolean;
    onselect?: (device_id: string) => void;
    /** "Show in Devices" on the detail card. */
    onselectdevice?: (device_id: string) => void;
    onfallback?: () => void;
    fallback?: Snippet;
  }
  let {
    plan = null,
    placements = [],
    devices = [],
    deviceInfo = {},
    presence = {},
    bandwidth = {},
    reducedMotion = false,
    visible = true,
    onselect,
    onselectdevice,
    onfallback,
    fallback
  }: Props = $props();

  interface RoomLabel { id: string; name: string; area: string; x: number; y: number }
  interface RoomHover { id: string; name: string; area: string; x: number; y: number }

  let mode = $state<'pending' | '3d' | 'fallback'>('pending');
  let selected = $state<string | null>(null);
  let selectedRoomId = $state<string | null>(null);
  let hoverRoom = $state<RoomHover | null>(null);
  let labels = $state<RoomLabel[]>([]);
  let viewportEl = $state<HTMLDivElement | null>(null);
  let cardEl = $state<HTMLElement | null>(null);
  let hoverPin = $state<{ id: string; name: string; x: number; y: number } | null>(null);
  let activePreset = $state<CameraPresetName | null>('iso');
  let wallsHidden = $state(false);
  let isolatedFloorId = $state<string | null>(null);
  let prefersReduced = $state(false);
  const reduced = $derived(reducedMotion || prefersReduced);
  // Test-observable counters: the scene rebuilds when geometry changes; the
  // camera resets only when the PLAN changes (audit H-5).
  let rebuildCount = $state(0);
  let resetCount = $state(0);
  let loopRunning = $state(false);
  /** True while the GPU context is lost: the picture is frozen, and the card says so instead of showing a stale scene as live. */
  let contextLost = $state(false);
  let contextTimer: ReturnType<typeof setTimeout> | undefined;
  let hoverFrame = 0;
  let pendingHover: PointerEvent | null = null;

  const sceneDesc = $derived<SceneDescription>(
    plan ? buildSceneDescription(plan, placements, devices) : { floors: [], bounds: null }
  );
  const allPins = $derived<DevicePin[]>(sceneDesc.floors.flatMap((floor) => floor.pins));
  const card = $derived<PinCard | null>(
    selected === null
      ? null
      : (() => {
          const pin = allPins.find((candidate) => candidate.device_id === selected);
          if (!pin) return null;
          return buildPinCard(
            pin,
            plan,
            devices.find((device) => device.device_id === selected),
            deviceInfo[selected],
            presence[selected]
          );
        })()
  );

  // --- three.js plumbing (plain, non-reactive; effects gate on `mode`) -----
  let stage = $state<HTMLDivElement | null>(null);
  let canvas = $state<HTMLCanvasElement | null>(null);
  let renderer: TwinRenderer | null = null;
  let scene: THREE.Scene | null = null;
  let camera: THREE.PerspectiveCamera | null = null;
  let palette: TwinPalette = readTwinPalette(null);
  let staticRoot: THREE.Group | null = null;
  let shadowTexture: THREE.DataTexture | null = null;
  let floorNodes = new Map<string, { group: THREE.Group; walls: THREE.Group }>();
  let pinNodes = new Map<string, { pin: THREE.Mesh; ring: THREE.Mesh; hit: THREE.Mesh; glow: THREE.Sprite; halo: THREE.Sprite; floor_id: string; pulse: number }>();
  let extentMeshes: { floor_id: string; mesh: THREE.Mesh }[] = [];
  const occlusionRay = new THREE.Raycaster();
  const scratch = new THREE.Vector3();
  const scratchWorld = new THREE.Vector3();
  const scratchDir = new THREE.Vector3();
  const blockerBuffer: THREE.Mesh[] = [];
  const visibleExtents: { level: number; mesh: THREE.Mesh }[] = [];
  // Pickable meshes of the visible floors, rebuilt only when visibility or the scene changes (never per pointer move).
  let pickPins: THREE.Mesh[] = [];
  let pickRooms: THREE.Mesh[] = [];
  let roomNodes = new Map<string, { mesh: THREE.Mesh; material: THREE.MeshBasicMaterial; anchor: Vec2; floor_id: string; name: string; area_m2: number | undefined; polygon: Vec2[]; elevation: number }>();
  // Walls grouped per wall so every segment of one wall cuts down together.
  let wallNodes: { floor_id: string; mid: Vec2; cut: boolean; parts: { mesh: THREE.Mesh; base: number; height: number }[] }[] = [];
  // Floor materials with their base colour, so floors below the focus dim without alpha.
  let dimmables: { floor_id: string; material: THREE.Material & { color: THREE.Color }; base: THREE.Color }[] = [];
  let glowTexture: THREE.DataTexture | null = null;
  let ringTexture: THREE.DataTexture | null = null;
  const prevPresence = new Map<string, PresenceState>();
  const pulses = new Map<string, number>();

  // Orbit state: spherical coordinates around a target point.
  const target = new THREE.Vector3(0, 1, 0);
  let theta = -Math.PI / 4;
  let phi = 1.05;
  let radius = 14;
  let tween: { from: CameraPose; to: CameraPose; start: number } | null = null;
  let rafHandle = 0;
  let dirty = true;
  // The camera starts from the bounds only for a different home (or the first plan); an edit snapshot of the same home keeps the view.
  let lastHomeId: string | null | undefined;
  let resizeObserver: ResizeObserver | null = null;
  let dragging: 'orbit' | 'pan' | null = null;
  let dragMoved = 0;
  let lastPointer = { x: 0, y: 0 };
  const raycaster = new THREE.Raycaster();

  function currentPose(): CameraPose {
    return { theta, phi, radius, target: { x: target.x, y: target.y, z: target.z } };
  }
  function applyPose(pose: CameraPose) {
    theta = pose.theta;
    phi = pose.phi;
    radius = pose.radius;
    target.set(pose.target.x, pose.target.y, pose.target.z);
  }
  /** Moves the camera; animated unless reduced motion or no render loop is running. */
  function moveTo(pose: CameraPose, instant = false) {
    if (instant || reduced || !rafHandle) {
      tween = null;
      applyPose(pose);
      requestRender();
    } else {
      tween = { from: currentPose(), to: pose, start: performance.now() };
      dirty = true;
    }
  }

  /** Dollhouse cut: camera-side walls drop to short stubs; far walls stay tall. */
  function updateWallCut() {
    if (wallNodes.length === 0 || !sceneDesc.bounds) return;
    const toCamera = { x: Math.cos(theta), y: Math.sin(theta) };
    const center = sceneDesc.bounds.center;
    for (const node of wallNodes) {
      const cut = wallIsCut(node.mid, center, toCamera, phi);
      if (cut === node.cut) continue;
      node.cut = cut;
      for (const part of node.parts) {
        const stub = cut ? stubbedBox(part.base, part.height, WALL_STUB_M) : { base: part.base, height: part.height };
        part.mesh.visible = stub !== null;
        if (stub) {
          part.mesh.scale.y = stub.height / part.height;
          part.mesh.position.y = stub.base + stub.height / 2;
        }
      }
    }
  }

  /** Pins keep a minimum on-screen size: scale with camera distance, capped up close. */
  function applyPinScale() {
    if (!camera) return;
    const height = stage?.clientHeight || 420;
    for (const [id, node] of pinNodes) {
      node.pin.getWorldPosition(scratchWorld);
      const zoom = pinScreenScale(camera.position.distanceTo(scratchWorld), camera.fov, height);
      const isSelected = selected === id;
      node.pin.scale.setScalar(zoom * (isSelected ? 1.3 : 1) * node.pulse);
      node.hit.scale.setScalar(zoom);
      node.glow.scale.setScalar(0.6 * zoom);
      node.halo.scale.setScalar((isSelected ? 0.78 : 0.56) * zoom);
    }
  }

  /** Projects each room's anchor to the canvas; DOM labels follow, culled for room on screen. */
  function updateLabels() {
    if (!camera || !stage) return;
    const next: RoomLabel[] = [];
    if (labelsVisibleForPhi(phi) && roomNodes.size > 0) {
      const width = stage.clientWidth || 640;
      const height = stage.clientHeight || 420;
      camera.updateMatrixWorld();
      visibleExtents.length = 0;
      for (const entry of extentMeshes) if (floorVisible(entry.floor_id)) visibleExtents.push({ level: floorLevel(entry.floor_id), mesh: entry.mesh });
      const candidates: LabelCandidate[] = [];
      for (const [id, node] of roomNodes) {
        if (!floorVisible(node.floor_id)) continue;
        scratchWorld.set(node.anchor.x, node.elevation + 0.15, node.anchor.y);
        const distance = camera.position.distanceTo(scratchWorld);
        scratch.copy(scratchWorld).project(camera);
        if (scratch.z < -1 || scratch.z > 1) continue;
        // A floor above this label's room hides it: test the ray against those slabs.
        const level = floorLevel(node.floor_id);
        blockerBuffer.length = 0;
        for (const entry of visibleExtents) if (entry.level > level) blockerBuffer.push(entry.mesh);
        if (blockerBuffer.length > 0) {
          occlusionRay.set(camera.position, scratchDir.copy(scratchWorld).sub(camera.position).normalize());
          occlusionRay.far = Math.max(0, distance - 0.05);
          if (occlusionRay.intersectObjects(blockerBuffer, false).length > 0) continue;
        }
        const size = estimateLabelSize(node.name, node.area_m2 !== undefined);
        candidates.push({
          id,
          x: Math.round((scratch.x * 0.5 + 0.5) * width),
          y: Math.round((-scratch.y * 0.5 + 0.5) * height),
          ...size,
          priority: node.area_m2 ?? 0
        });
      }
      const rects = [];
      if (cardEl && viewportEl) {
        const card = cardEl.getBoundingClientRect();
        const view = viewportEl.getBoundingClientRect();
        if (card.width > 0) rects.push({ x: card.left - view.left, y: card.top - view.top, w: card.width, h: card.height });
      }
      const keep = cullLabels(candidates, { w: width, h: height }, rects);
      for (const candidate of candidates) {
        if (!keep.has(candidate.id)) continue;
        const node = roomNodes.get(candidate.id)!;
        next.push({ id: candidate.id, name: node.name, area: formatArea(node.area_m2), x: candidate.x, y: candidate.y });
      }
    }
    const same = next.length === labels.length && next.every((label, i) => {
      const old = labels[i]!;
      return old.id === label.id && old.x === label.x && old.y === label.y;
    });
    if (!same) labels = next;
  }

  function applyCamera() {
    if (!camera) return;
    camera.position.set(
      target.x + radius * Math.sin(phi) * Math.cos(theta),
      target.y + radius * Math.cos(phi),
      target.z + radius * Math.sin(phi) * Math.sin(theta)
    );
    camera.lookAt(target);
    updateWallCut();
    applyPinScale();
    updateLabels();
  }

  function renderFrame() {
    if (contextLost) return;
    if (renderer && scene && camera) renderer.render(scene, camera);
  }

  function requestRender() {
    // Without a loop (reduced motion, hidden panel) changes render exactly
    // once; with a loop they mark the next frame dirty.
    dirty = true;
    if (!rafHandle && mode === '3d' && !contextLost) {
      applyCamera();
      renderFrame();
      dirty = false;
    }
  }

  function stopLoop() {
    if (rafHandle) cancelAnimationFrame(rafHandle);
    rafHandle = 0;
    loopRunning = false;
  }

  function startLoop() {
    stopLoop();
    const tick = (now: number) => {
      const animating = pulses.size > 0 || tween !== null;
      if (animating) stepAnimations(now);
      // Render only when something changed: an idle scene costs no GPU time.
      if (dirty || animating) {
        applyCamera();
        renderFrame();
        dirty = false;
      }
      rafHandle = requestAnimationFrame(tick);
    };
    rafHandle = requestAnimationFrame(tick);
    loopRunning = true;
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
        node.pulse = 1;
      } else {
        node.pulse = 1 + 0.35 * Math.sin(Math.PI * k);
      }
    }
    if (tween) {
      const { k, done } = tweenProgress(tween.start, now);
      applyPose(lerpPose(tween.from, tween.to, k));
      if (done) tween = null;
    }
  }

  function aspect(): number {
    return camera?.aspect ?? 4 / 3;
  }

  function goPreset(name: CameraPresetName, instant = false) {
    activePreset = name;
    moveTo(presetPose(name, sceneDesc, aspect(), undefined, EXPLODE_GAP_M), instant);
  }

  function resetView(instant = true) {
    tween = null;
    resetCount += 1;
    goPreset('iso', instant);
  }

  /** World height of a floor's walking surface, including the exploded-stack gap. */
  function floorElevation(floor_id: string): number {
    const index = sceneDesc.floors.findIndex((floor) => floor.floor_id === floor_id);
    return index < 0 ? 0 : sceneDesc.floors[index]!.elevation_m + index * EXPLODE_GAP_M;
  }

  /** Frames the selected device or room; with nothing selected, the whole home. */
  function frameSelection() {
    const pin = selected ? allPins.find((candidate) => candidate.device_id === selected) : undefined;
    if (pin) {
      const y = floorElevation(pin.floor_id) + pin.height_m;
      const box = boxAround([{ x: pin.position.x, y, z: pin.position.y }], 1.4);
      activePreset = null;
      moveTo(framePose(box, { theta, phi }, aspect()));
      return;
    }
    const room = selectedRoomId ? roomNodes.get(selectedRoomId) : undefined;
    if (room) {
      const box = boxAround(
        room.polygon.map((point) => ({ x: point.x, y: room.elevation + 1.2, z: point.y })),
        0.5
      );
      activePreset = null;
      moveTo(framePose(box, { theta, phi }, aspect()));
      return;
    }
    const whole = sceneBox(sceneDesc, EXPLODE_GAP_M);
    if (whole) {
      activePreset = null;
      moveTo(framePose(whole, { theta, phi }, aspect(), undefined, 4));
    }
  }

  function select(device_id: string) {
    selected = device_id;
    selectedRoomId = null;
    onselect?.(device_id);
    const pin = allPins.find((candidate) => candidate.device_id === device_id);
    if (pin && sceneDesc.floors.length > 1) isolatedFloorId = pin.floor_id; // selecting focuses its floor
    if (pin && mode === '3d') {
      const y = floorElevation(pin.floor_id) + pin.height_m;
      activePreset = null;
      moveTo({ theta, phi, radius: Math.min(radius, 7.5), target: { x: pin.position.x, y, z: pin.position.y } });
    }
  }

  function clearSelection() {
    selected = null;
    selectedRoomId = null;
  }

  // --- Pointer / wheel / keyboard controls ---------------------------------
  function onPointerDown(event: PointerEvent) {
    dragging = event.button === 2 || event.shiftKey ? 'pan' : 'orbit';
    dragMoved = 0;
    lastPointer = { x: event.clientX, y: event.clientY };
    (event.currentTarget as HTMLElement | null)?.setPointerCapture?.(event.pointerId);
  }

  function onPointerMove(event: PointerEvent) {
    // A drag whose button is no longer down (cancelled touch, release outside the window) must not keep steering the camera.
    if (dragging && event.buttons === 0 && event.pointerType !== 'touch') dragging = null;
    if (!dragging) {
      // Raycasting every pointer event is wasted work: coalesce to one hover test per frame.
      pendingHover = event;
      if (!hoverFrame) hoverFrame = requestAnimationFrame(() => { hoverFrame = 0; const next = pendingHover; pendingHover = null; if (next) hoverAt(next); });
      return;
    }
    const dx = event.clientX - lastPointer.x;
    const dy = event.clientY - lastPointer.y;
    lastPointer = { x: event.clientX, y: event.clientY };
    dragMoved += Math.abs(dx) + Math.abs(dy);
    if (dragMoved > 5) {
      tween = null;
      activePreset = null;
      if (hoverRoom) hoverRoom = null;
      if (hoverPin) hoverPin = null;
    }
    if (dragging === 'orbit') {
      theta -= dx * 0.005;
      phi = Math.min(PHI_MAX, Math.max(PHI_MIN, phi - dy * 0.005));
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

  function onPointerLeave() {
    pendingHover = null;
    if (hoverRoom) hoverRoom = null;
    if (hoverPin) hoverPin = null;
  }

  /** The browser took the pointer away (touch cancel, capture lost): end the drag exactly as a release would, without picking. */
  function endDrag() {
    dragging = null;
    dragMoved = 0;
  }

  function onWheel(event: WheelEvent) {
    event.preventDefault();
    tween = null;
    radius = Math.min(RADIUS_MAX, Math.max(RADIUS_MIN, radius * (1 + event.deltaY * 0.001)));
    requestRender();
  }

  function onKeyDown(event: KeyboardEvent) {
    const step = 0.15;
    if (event.key === 'Escape') {
      if (selected === null && selectedRoomId === null) return;
      clearSelection();
      event.preventDefault();
      return;
    }
    if (event.key === 'ArrowLeft') theta -= step;
    else if (event.key === 'ArrowRight') theta += step;
    else if (event.key === 'ArrowUp') phi = Math.max(PHI_MIN, phi - step);
    else if (event.key === 'ArrowDown') phi = Math.min(PHI_MAX, phi + step);
    else if (event.key === '+' || event.key === '=') radius = Math.max(RADIUS_MIN, radius * 0.9);
    else if (event.key === '-') radius = Math.min(RADIUS_MAX, radius * 1.1);
    else return;
    tween = null;
    if (event.key.startsWith('Arrow')) activePreset = null;
    event.preventDefault();
    requestRender();
  }

  function pointerRay(event: PointerEvent): boolean {
    if (!camera || !canvas) return false;
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;
    const pointer = new THREE.Vector2(
      ((event.clientX - rect.left) / rect.width) * 2 - 1,
      -((event.clientY - rect.top) / rect.height) * 2 + 1
    );
    camera.updateMatrixWorld();
    raycaster.setFromCamera(pointer, camera);
    return true;
  }

  function floorLevel(floor_id: string): number {
    return sceneDesc.floors.find((floor) => floor.floor_id === floor_id)?.level ?? 0;
  }
  /** With a floor focused, floors above it are hidden. */
  function floorVisible(floor_id: string): boolean {
    return isolatedFloorId === null || floorLevel(floor_id) <= floorLevel(isolatedFloorId);
  }

  function pickPin(): string | null {
    const hits = raycaster.intersectObjects(pickPins, false);
    const hit = hits.find((candidate) => typeof candidate.object.userData.device_id === 'string');
    return hit ? (hit.object.userData.device_id as string) : null;
  }

  function pickRoom(): string | null {
    const hits = raycaster.intersectObjects(pickRooms, false);
    const hit = hits.find((candidate) => typeof candidate.object.userData.room_id === 'string');
    return hit ? (hit.object.userData.room_id as string) : null;
  }

  function hoverAt(event: PointerEvent) {
    if ((roomNodes.size === 0 && pinNodes.size === 0) || !pointerRay(event)) return;
    const rect = stage?.getBoundingClientRect();
    const x = event.clientX - (rect?.left ?? 0);
    const y = event.clientY - (rect?.top ?? 0);
    const pinId = pickPin();
    if (pinId) {
      const label = allPins.find((pin) => pin.device_id === pinId)?.label ?? 'Device';
      hoverPin = { id: pinId, name: label, x, y };
      if (hoverRoom) hoverRoom = null;
      return;
    }
    if (hoverPin) hoverPin = null;
    const roomId = pickRoom();
    if (roomId === null) {
      if (hoverRoom) hoverRoom = null;
      return;
    }
    const node = roomNodes.get(roomId)!;
    hoverRoom = { id: roomId, name: node.name, area: formatArea(node.area_m2), x, y };
  }

  function pickAt(event: PointerEvent) {
    if (!pointerRay(event)) return;
    const pinId = pickPin();
    if (pinId) {
      select(pinId);
      return;
    }
    const roomId = pickRoom();
    selected = null;
    selectedRoomId = roomId;
    const picked = roomId ? roomNodes.get(roomId) : undefined;
    if (picked && sceneDesc.floors.length > 1) isolatedFloorId = picked.floor_id;
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

  /** Flat, upward-facing triangulated polygon (handles concave rooms). */
  function polygonGeometry(polygon: Vec2[]): THREE.BufferGeometry | null {
    const triangles = triangulatePolygon(polygon);
    if (triangles.length === 0) return null;
    const positions = new Float32Array(polygon.length * 3);
    const normals = new Float32Array(polygon.length * 3);
    polygon.forEach((point, index) => {
      positions[index * 3] = point.x;
      positions[index * 3 + 2] = point.y; // plan y -> three z
      normals[index * 3 + 1] = 1;
    });
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('normal', new THREE.BufferAttribute(normals, 3));
    geometry.setIndex(triangles.flat());
    return geometry;
  }

  function slabBounds(slab: SlabDesc) {
    let minX = Infinity; let minY = Infinity; let maxX = -Infinity; let maxY = -Infinity;
    for (const point of slab.polygon) {
      minX = Math.min(minX, point.x); maxX = Math.max(maxX, point.x);
      minY = Math.min(minY, point.y); maxY = Math.max(maxY, point.y);
    }
    return { minX, minY, maxX, maxY };
  }

  /** Soft radial blob, built from raw pixels so it needs no 2D canvas. */
  function makeShadowTexture(): THREE.DataTexture {
    const size = 64;
    const data = new Uint8Array(size * size * 4);
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        const d = Math.hypot((x + 0.5) / size - 0.5, (y + 0.5) / size - 0.5) * 2;
        const falloff = Math.max(0, 1 - d);
        const alpha = falloff * falloff * (3 - 2 * falloff); // smoothstep
        const offset = (y * size + x) * 4;
        data[offset + 3] = Math.round(alpha * 255);
      }
    }
    const texture = new THREE.DataTexture(data, size, size, THREE.RGBAFormat);
    texture.needsUpdate = true;
    return texture;
  }

  /** Radial glow (filled) or thin ring, as raw white pixels tinted by the sprite colour. */
  function makeSpriteTexture(kind: 'glow' | 'ring'): THREE.DataTexture {
    const size = 64;
    const data = new Uint8Array(size * size * 4).fill(255);
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        const d = Math.hypot((x + 0.5) / size - 0.5, (y + 0.5) / size - 0.5) * 2;
        const alpha = kind === 'glow' ? Math.pow(Math.max(0, 1 - d), 2) : Math.max(0, 1 - Math.abs(d - 0.82) / 0.1);
        data[(y * size + x) * 4 + 3] = Math.round(Math.min(1, alpha) * 255);
      }
    }
    const texture = new THREE.DataTexture(data, size, size, THREE.RGBAFormat);
    texture.needsUpdate = true;
    return texture;
  }

  function rebuildStatic(desc: SceneDescription) {
    if (!scene) return;
    if (staticRoot) {
      scene.remove(staticRoot);
      disposeObject(staticRoot);
    }
    shadowTexture?.dispose();
    glowTexture?.dispose();
    ringTexture?.dispose();
    shadowTexture = makeShadowTexture();
    glowTexture = makeSpriteTexture('glow');
    ringTexture = makeSpriteTexture('ring');
    floorNodes = new Map();
    pinNodes = new Map();
    roomNodes = new Map();
    wallNodes = [];
    dimmables = [];
    extentMeshes = [];
    hoverRoom = null;
    hoverPin = null;
    staticRoot = new THREE.Group();
    const wallSide = new THREE.Color(palette.ink).lerp(new THREE.Color(palette.ambient), 0.4);
    const outline = new THREE.Color(palette.ink).lerp(new THREE.Color(palette.raised), 0.45);
    desc.floors.forEach((floor, floorIndex) => {
      const tint = (material: THREE.Material & { color: THREE.Color }) => {
        dimmables.push({ floor_id: floor.floor_id, material, base: material.color.clone() });
        return material;
      };
      const group = new THREE.Group();
      group.position.y = floor.elevation_m + floorIndex * EXPLODE_GAP_M;
      const walls = new THREE.Group();
      for (const slab of floor.slabs) {
        if (slab.kind === 'extent') {
          // A real slab: dark navy glass, unlit so the warm key never tints it.
          const { minX, minY, maxX, maxY } = slabBounds(slab);
          const top = tint(new THREE.MeshBasicMaterial({ color: palette.raised, toneMapped: false }));
          const edge = tint(new THREE.MeshBasicMaterial({ color: new THREE.Color(palette.raised).multiplyScalar(0.55), toneMapped: false }));
          const mesh = new THREE.Mesh(
            new THREE.BoxGeometry(maxX - minX, SLAB_THICKNESS_M, maxY - minY),
            [edge, edge, top, edge, edge, edge]
          );
          mesh.position.set((minX + maxX) / 2, -SLAB_THICKNESS_M / 2, (minY + maxY) / 2);
          extentMeshes.push({ floor_id: floor.floor_id, mesh });
          group.add(mesh);
          continue;
        }
        const geometry = polygonGeometry(slab.polygon);
        if (!geometry) continue;
        const material = new THREE.MeshBasicMaterial({
          color: new THREE.Color(palette.raised).lerp(new THREE.Color(palette.ink), 0.03),
          toneMapped: false,
          side: THREE.DoubleSide
        });
        tint(material);
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.y = 0.012;
        // A thin light outline keeps every room individually readable from above.
        const edge = new THREE.LineLoop(
          new THREE.BufferGeometry().setFromPoints(slab.polygon.map((point) => new THREE.Vector3(point.x, 0.03, point.y))),
          tint(new THREE.LineBasicMaterial({ color: outline }))
        );
        group.add(edge);
        if (slab.room_id) {
          mesh.userData.room_id = slab.room_id;
          roomNodes.set(slab.room_id, {
            mesh,
            material,
            anchor: labelAnchor(slab.polygon),
            floor_id: floor.floor_id,
            name: slab.name?.trim() ? slab.name : 'Unnamed room',
            area_m2: slab.area_m2,
            polygon: slab.polygon,
            elevation: floor.elevation_m + floorIndex * EXPLODE_GAP_M
          });
        }
        group.add(mesh);
      }
      if (floor.ceiling) {
        const { minX, minY, maxX, maxY } = slabBounds(floor.ceiling);
        const plane = new THREE.Mesh(
          new THREE.PlaneGeometry(maxX - minX, maxY - minY),
          new THREE.MeshBasicMaterial({ color: palette.fill, transparent: true, opacity: 0.04, side: THREE.DoubleSide, depthWrite: false })
        );
        plane.rotation.x = Math.PI / 2;
        plane.position.set((minX + maxX) / 2, floor.ceiling_m, (minY + maxY) / 2);
        walls.add(plane); // hidden with the walls
      }
      const byWall = new Map<string, (typeof wallNodes)[number]>();
      const sums = new Map<string, { x: number; y: number; n: number }>();
      for (const box of floor.walls) {
        const tone = wallSide.clone();
        tone.offsetHSL(0, 0, (unitHash(box.wall_id) - 0.5) * 0.06);
        const side = tint(new THREE.MeshStandardMaterial({ color: tone, roughness: wallRoughness(box.wall_id), metalness: 0 }));
        // The cap is unlit and brighter than the sides, so the plan reads from above.
        const cap = tint(new THREE.MeshBasicMaterial({ color: palette.ink, toneMapped: false }));
        const mesh = new THREE.Mesh(new THREE.BoxGeometry(box.length_m, box.height_m, box.thickness_m), [side, side, cap, side, side, side]);
        mesh.position.set(box.center.x, box.base_m + box.height_m / 2, box.center.y);
        mesh.rotation.y = -box.angle_rad;
        walls.add(mesh);
        let node = byWall.get(box.wall_id);
        if (!node) {
          node = { floor_id: floor.floor_id, mid: { x: 0, y: 0 }, cut: false, parts: [] };
          byWall.set(box.wall_id, node);
          sums.set(box.wall_id, { x: 0, y: 0, n: 0 });
          wallNodes.push(node);
        }
        node.parts.push({ mesh, base: box.base_m, height: box.height_m });
        const sum = sums.get(box.wall_id)!;
        sum.x += box.center.x; sum.y += box.center.y; sum.n += 1;
      }
      for (const [id, node] of byWall) {
        const sum = sums.get(id)!;
        node.mid = { x: sum.x / sum.n, y: sum.y / sum.n };
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
        const blob = contactShadow(pin.height_m);
        const shadow = new THREE.Mesh(
          new THREE.PlaneGeometry(blob.radius * 2, blob.radius * 2),
          new THREE.MeshBasicMaterial({ color: '#000000', map: shadowTexture, transparent: true, opacity: blob.opacity, depthWrite: false })
        );
        shadow.rotation.x = -Math.PI / 2;
        shadow.position.set(pin.position.x, 0.024, pin.position.y);
        shadow.renderOrder = 1;
        group.add(shadow);
        // A thin stem ties the pin to the floor so its height reads.
        const stem = new THREE.Mesh(
          new THREE.CylinderGeometry(0.012, 0.012, Math.max(pin.height_m, 0.02), 6),
          new THREE.MeshBasicMaterial({ color: palette.ink, toneMapped: false })
        );
        stem.position.set(pin.position.x, Math.max(pin.height_m, 0.02) / 2, pin.position.y);
        group.add(stem);
        const mesh = new THREE.Mesh(
          new THREE.SphereGeometry(0.13, 20, 14),
          // Neutral at build time; the live-state effect applies heat colors. Unlit and
          // untone-mapped so the heat tier colour is exactly what shows.
          new THREE.MeshBasicMaterial({ color: heatColor(null), toneMapped: false })
        );
        mesh.position.set(pin.position.x, pin.height_m, pin.position.y);
        mesh.userData.device_id = pin.device_id;
        const glow = new THREE.Sprite(
          new THREE.SpriteMaterial({ map: glowTexture, color: heatColor(null), transparent: true, opacity: 0.7, depthWrite: false, blending: THREE.AdditiveBlending, toneMapped: false })
        );
        glow.scale.setScalar(0.85);
        glow.position.copy(mesh.position);
        const halo = new THREE.Sprite(
          new THREE.SpriteMaterial({ map: ringTexture, color: palette.highlight, transparent: true, opacity: 1, depthWrite: false, toneMapped: false })
        );
        halo.scale.setScalar(0.62);
        halo.position.copy(mesh.position);
        halo.visible = false;
        // A generous invisible target keeps small pins easy to click.
        const hit = new THREE.Mesh(new THREE.SphereGeometry(0.32, 8, 6), new THREE.MeshBasicMaterial({ visible: false }));
        hit.position.copy(mesh.position);
        hit.userData.device_id = pin.device_id;
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(0.2, 0.27, 24),
          new THREE.MeshBasicMaterial({ color: palette.key, side: THREE.DoubleSide })
        );
        ring.geometry.rotateX(-Math.PI / 2);
        ring.position.set(pin.position.x, pin.height_m - 0.05, pin.position.y);
        ring.visible = false;
        group.add(glow, mesh, halo, ring, hit);
        pinNodes.set(pin.device_id, { pin: mesh, ring, hit, glow, halo, floor_id: floor.floor_id, pulse: 1 });
      }
      for (const cone of floor.cones) {
        const coneRadius = Math.tan(cone.half_angle_rad) * cone.length_m;
        const geometry = new THREE.ConeGeometry(coneRadius, cone.length_m, 20, 1, true);
        geometry.rotateX(Math.PI); // apex toward local -y ... then re-center
        geometry.translate(0, cone.length_m / 2, 0); // apex at origin, base at +y
        const mesh = new THREE.Mesh(
          geometry,
          new THREE.MeshBasicMaterial({ color: palette.fill, transparent: true, opacity: 0.14, side: THREE.DoubleSide })
        );
        const direction = new THREE.Vector3(cone.direction.x, cone.direction.z, cone.direction.y);
        mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
        mesh.position.set(cone.apex.x, cone.apex.h, cone.apex.y);
        group.add(mesh);
      }
      group.add(walls);
      staticRoot!.add(group);
      floorNodes.set(floor.floor_id, { group, walls });
    });
    scene.add(staticRoot);
    applyVisibility();
    applyDim();
    applyRoomHighlight();
    rebuildCount += 1;
  }

  /** Focus a floor: floors above it are hidden (floorVisible), floors below dim. */
  function applyVisibility() {
    for (const [floor_id, node] of floorNodes) {
      node.group.visible = floorVisible(floor_id);
      node.walls.visible = !wallsHidden;
    }
    pickPins = [];
    for (const node of pinNodes.values()) if (floorVisible(node.floor_id)) pickPins.push(node.hit);
    pickRooms = [];
    for (const node of roomNodes.values()) if (floorVisible(node.floor_id)) pickRooms.push(node.mesh);
  }

  /** Dimming multiplies base colours, so it stays opaque and pixel-deterministic. */
  function applyDim() {
    const focusLevel = isolatedFloorId === null ? null : floorLevel(isolatedFloorId);
    for (const entry of dimmables) {
      const factor = focusLevel !== null && floorLevel(entry.floor_id) < focusLevel ? 0.32 : 1;
      entry.material.color.copy(entry.base).multiplyScalar(factor);
    }
    const highlight = new THREE.Color(palette.highlight);
    for (const [id, node] of roomNodes) {
      const amount = hoverRoom?.id === id ? 0.5 : selectedRoomId === id ? 0.35 : 0;
      if (amount > 0) node.material.color.lerp(highlight, amount);
    }
  }

  function applyRoomHighlight() {
    applyDim();
  }

  function updatePins(now: number) {
    for (const pin of allPins) {
      const node = pinNodes.get(pin.device_id);
      const state = presence[pin.device_id] ?? 'unknown';
      const previous = prevPresence.get(pin.device_id);
      if (previous !== undefined && previous !== state && !reduced) { pulses.set(pin.device_id, now); dirty = true; }
      prevPresence.set(pin.device_id, state);
      if (!node) continue;
      const tier = heatColor(bandwidth[pin.device_id] ?? null);
      // The "unavailable" tier renders as a bright neutral with a ring, never dull grey.
      const unavailable = tier === HEAT_UNAVAILABLE_COLOR;
      const color = unavailable ? palette.ink : tier;
      (node.pin.material as THREE.MeshBasicMaterial).color.set(color);
      const quiet = state === 'offline' || state === 'unknown';
      const glow = node.glow.material as THREE.SpriteMaterial;
      glow.color.set(color);
      glow.opacity = quiet ? 0.3 : 0.55;
      const isSelected = selected === pin.device_id;
      node.halo.visible = isSelected || unavailable;
      const haloMaterial = node.halo.material as THREE.SpriteMaterial;
      haloMaterial.color.set(isSelected ? palette.highlight : palette.ink);
      const badge = riskBadge(riskFromPresence(state));
      node.ring.visible = badge.ring;
      (node.ring.material as THREE.MeshBasicMaterial).color.set(badge.outline);
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
    palette = readTwinPalette();
    scene = new THREE.Scene();
    // Cool ambient from below-left, warm key from the camera's right: faces
    // the default view sees get the warm side, shaded faces stay cool.
    scene.add(new THREE.HemisphereLight(palette.ambient, palette.ground, 1.1));
    const key = new THREE.DirectionalLight(new THREE.Color(palette.key).lerp(new THREE.Color('#ffffff'), 0.45), 5.4);
    key.position.set(12, 4.5, -2);
    scene.add(key);
    const fill = new THREE.DirectionalLight(palette.fill, 0.55);
    fill.position.set(-6, 5, -10);
    scene.add(fill);
    camera = new THREE.PerspectiveCamera(50, 4 / 3, 0.1, 500);
    mode = '3d';
    const onContextLost = (event: Event) => {
      // preventDefault asks the browser to restore the context; three.js re-initialises itself when it does.
      event.preventDefault();
      contextLost = true;
      stopLoop();
      clearTimeout(contextTimer);
      // Not restored in time: stop pretending and hand over to the honest 2D fallback.
      contextTimer = setTimeout(() => { if (contextLost) { mode = 'fallback'; onfallback?.(); } }, 5000);
    };
    const onContextRestored = () => {
      clearTimeout(contextTimer);
      contextLost = false;
      dirty = true;
      if (visible && !reduced) startLoop();
      requestRender();
    };
    targetCanvas?.addEventListener('webglcontextlost', onContextLost);
    targetCanvas?.addEventListener('webglcontextrestored', onContextRestored);
    window.addEventListener('resize', resize);
    // The stage can change size while its panel is hidden (a window resize
    // fires, but the hidden stage measures 0); observe the element itself.
    if (typeof ResizeObserver === 'function' && stage) {
      resizeObserver = new ResizeObserver(() => resize());
      resizeObserver.observe(stage);
    }
    resize();
    return () => {
      stopLoop();
      clearTimeout(contextTimer);
      if (hoverFrame) cancelAnimationFrame(hoverFrame);
      hoverFrame = 0;
      targetCanvas?.removeEventListener('webglcontextlost', onContextLost);
      targetCanvas?.removeEventListener('webglcontextrestored', onContextRestored);
      window.removeEventListener('resize', resize);
      resizeObserver?.disconnect();
      resizeObserver = null;
      if (staticRoot) disposeObject(staticRoot);
      shadowTexture?.dispose();
      shadowTexture = null;
      glowTexture?.dispose();
      ringTexture?.dispose();
      glowTexture = null;
      ringTexture = null;
      renderer?.dispose();
      renderer?.forceContextLoss?.();
      renderer = null;
      scene = null;
      camera = null;
    };
  });

  $effect(() => {
    if (mode !== '3d') return;
    const desc = sceneDesc; // tracked read; the work below must not track more
    const currentPlan = plan;
    untrack(() => {
      rebuildStatic(desc);
      if ((currentPlan?.home_id ?? null) !== lastHomeId) {
        // A different home: start the camera from its bounds.
        lastHomeId = currentPlan?.home_id ?? null;
        prevPresence.clear();
        resetView(true);
      }
      // Fresh pin meshes need their live colors before the next frame.
      updatePins(typeof performance !== 'undefined' ? performance.now() : 0);
      requestRender();
    });
  });

  $effect(() => {
    if (mode !== '3d') return;
    void wallsHidden;
    void isolatedFloorId;
    applyVisibility();
    applyDim();
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void hoverRoom?.id;
    void selectedRoomId;
    applyDim();
    applyRoomHighlight();
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void card; // the card hides labels it would cover
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void presence;
    void bandwidth;
    void selected;
    applyDim();
    updatePins(typeof performance !== 'undefined' ? performance.now() : 0);
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    if (reduced || !visible) {
      stopLoop();
      if (visible) requestRender();
    } else {
      startLoop();
      requestRender();
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
  data-selected-room={selectedRoomId ?? ''}
  data-hover-room={hoverRoom?.id ?? ''}
  data-hover-pin={hoverPin?.id ?? ''}
  data-camera-preset={activePreset ?? ''}
  data-rebuild-count={rebuildCount}
  data-reset-count={resetCount}
  data-loop={loopRunning ? 'running' : 'stopped'}
  aria-label="3D home twin"
>
  {#if mode === '3d'}
    <div class="twin-toolbar" role="toolbar" aria-label="3D view controls">
      <button type="button" onclick={() => resetView(false)}>Reset view</button>
      <span class="twin-group" role="group" aria-label="Camera presets">
        <button type="button" aria-pressed={activePreset === 'top'} onclick={() => goPreset('top')}>Top</button>
        <button type="button" aria-pressed={activePreset === 'iso'} onclick={() => goPreset('iso')}>Isometric</button>
        <button type="button" aria-pressed={activePreset === 'front'} onclick={() => goPreset('front')}>Front</button>
        <button type="button" onclick={frameSelection}>Frame selection</button>
      </span>
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
  <div class="twin-viewport" class:stage-hidden={mode !== '3d'} bind:this={viewportEl}>
    <!-- The stage is a genuine custom widget (role="application" with full
         keyboard support); svelte's static a11y rules cannot see that. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="twin-stage"
      role="application"
      aria-label="Home model. Drag to orbit, shift-drag to pan, scroll to zoom, arrow keys to rotate. Hover a room for its name and area; click a device pin for details."
      tabindex={mode === '3d' ? 0 : -1}
      bind:this={stage}
      onpointerdown={onPointerDown}
      onpointermove={onPointerMove}
      onpointerup={onPointerUp}
      onpointercancel={endDrag}
      onlostpointercapture={endDrag}
      onpointerleave={onPointerLeave}
      onwheel={onWheel}
      onkeydown={onKeyDown}
    >
      <canvas bind:this={canvas}></canvas>
    </div>
    {#if mode === '3d' && contextLost}<div class="twin-lost" role="status">3D view paused: the graphics context was lost. Restoring it; the 2D plan still shows your devices.</div>{/if}
    {#if mode === '3d'}
      <div class="twin-labels" aria-label="Room labels">
        {#each labels as label (label.id)}
          <div class="twin-room-label" data-room-id={label.id} style:left="{label.x}px" style:top="{label.y}px">
            <strong>{label.name}</strong><span>{label.area}</span>
          </div>
        {/each}
      </div>
    {/if}
    {#if mode === '3d' && hoverRoom}
      <div
        class="twin-room-tip"
        role="status"
        style:left="{Math.min(hoverRoom.x + 14, (stage?.clientWidth ?? 600) - 150)}px"
        style:top="{Math.max(hoverRoom.y - 44, 6)}px"
      >
        <strong>{hoverRoom.name}</strong>
        <span>{hoverRoom.area}</span>
      </div>
    {/if}
    {#if mode === '3d' && hoverPin}
      <div
        class="twin-room-tip twin-pin-tip"
        role="status"
        style:left="{Math.min(hoverPin.x + 14, (stage?.clientWidth ?? 600) - 170)}px"
        style:top="{Math.max(hoverPin.y - 40, 6)}px"
      >
        <strong>{hoverPin.name}</strong>
      </div>
    {/if}
    {#if mode === '3d' && card}
      <aside class="twin-card" bind:this={cardEl} aria-label="Device details" data-device-id={card.device_id}>
        <header>
          <h3>{card.name}</h3>
          <button type="button" class="twin-card-close" aria-label="Close device details" onclick={clearSelection}>&times;</button>
        </header>
        <dl>
          <div><dt>Presence</dt><dd data-field="presence">{card.presence}</dd></div>
          <div><dt>Room</dt><dd data-field="room">{card.room}</dd></div>
          <div><dt>Evidence</dt><dd data-field="evidence">{card.evidence}</dd></div>
          <div><dt>Last seen</dt><dd data-field="last-seen">{card.lastSeen}</dd></div>
        </dl>
        {#if onselectdevice}
          <button type="button" class="twin-card-action" onclick={() => onselectdevice?.(card.device_id)}>Show in Devices</button>
        {/if}
      </aside>
    {/if}
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
  .twin-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .twin-group { display: inline-flex; gap: 0; }
  .twin-group button { border-radius: 0; margin-left: -1px; }
  .twin-group button:first-child { border-radius: 5px 0 0 5px; margin-left: 0; }
  .twin-group button:last-child { border-radius: 0 5px 5px 0; }
  .twin-toolbar button { border: 1px solid var(--line-strong); border-radius: 5px; color: var(--ink); background: var(--surface); min-height: 36px; padding: 0 11px; cursor: pointer; font-size: 12px; }
  .twin-toolbar button[aria-pressed='true'] { border-color: var(--accent); color: var(--accent); position: relative; z-index: 1; }
  .twin-toolbar button:focus-visible { outline: 3px solid var(--gold); outline-offset: 3px; }
  .twin-viewport { position: relative; }
  .twin-viewport.stage-hidden { display: none; }
  .twin-stage { height: clamp(340px, 62vh, 640px); border: 1px solid var(--line); border-radius: 7px; background: radial-gradient(ellipse at 50% 30%, var(--surface-raised) 0%, var(--surface) 45%, var(--bg) 100%); overflow: hidden; touch-action: none; }
  .twin-stage:focus-visible { outline: 3px solid var(--gold); outline-offset: 3px; }
  .twin-stage canvas { display: block; width: 100%; height: 100%; }
  .twin-labels { position: absolute; inset: 0; overflow: hidden; pointer-events: none; border-radius: 7px; }
  .twin-room-label { position: absolute; transform: translate(-50%, -50%); display: grid; justify-items: center; gap: 1px; padding: 3px 9px; border-radius: 999px; background: color-mix(in srgb, var(--bg) 72%, transparent); border: 1px solid color-mix(in srgb, var(--line-strong) 70%, transparent); color: var(--ink); white-space: nowrap; pointer-events: none; text-shadow: 0 1px 2px rgb(0 0 0 / 0.7); }
  .twin-room-label strong { font: 600 12px var(--font-display); letter-spacing: 0.01em; }
  .twin-room-label span { font: 10px var(--font-mono); color: var(--muted-strong); }
  .twin-room-tip { position: absolute; z-index: 2; display: grid; gap: 1px; padding: 6px 10px; border: 1px solid var(--line-strong); border-radius: 6px; background: color-mix(in srgb, var(--surface) 78%, transparent); backdrop-filter: blur(10px); color: var(--ink); font-size: 12px; pointer-events: none; white-space: nowrap; }
  .twin-room-tip span { color: var(--accent); font: 11px var(--font-mono); }
  .twin-card { position: absolute; z-index: 3; top: 12px; right: 12px; width: min(280px, calc(100% - 24px)); display: grid; gap: 10px; padding: 12px 14px 14px; border: 1px solid var(--line-strong); border-radius: var(--radius-lg, 12px); background: color-mix(in srgb, var(--surface) 72%, transparent); backdrop-filter: blur(16px) saturate(1.25); box-shadow: 0 10px 30px rgb(0 0 0 / 0.45), inset 0 1px 0 rgb(255 255 255 / 0.06); color: var(--ink); }
  .twin-card header { display: flex; align-items: start; justify-content: space-between; gap: 8px; }
  .twin-card h3 { margin: 0; font: 600 14px var(--font-display); overflow-wrap: anywhere; }
  .twin-card-close { border: 0; background: transparent; color: var(--muted-strong); font-size: 20px; line-height: 1; min-width: 32px; min-height: 32px; margin: -6px -8px 0 0; cursor: pointer; border-radius: 5px; }
  .twin-card-close:hover { color: var(--ink); }
  .twin-card-close:focus-visible, .twin-card-action:focus-visible { outline: 3px solid var(--gold); outline-offset: 2px; }
  .twin-card dl { margin: 0; display: grid; gap: 6px; }
  .twin-card dl > div { display: grid; grid-template-columns: 78px 1fr; gap: 8px; font-size: 12px; }
  .twin-card dt { color: var(--muted); }
  .twin-card dd { margin: 0; color: var(--ink); overflow-wrap: anywhere; }
  .twin-card-action { min-height: 38px; border: 1px solid var(--accent); border-radius: 6px; background: transparent; color: var(--accent); font: 600 12px var(--font-display); cursor: pointer; }
  .twin-card-action:hover { background: color-mix(in srgb, var(--accent) 14%, transparent); }
  .twin-lost { position: absolute; inset: auto 12px 12px 12px; z-index: 4; padding: 10px 12px; border: 1px solid var(--gold); border-radius: 8px; background: color-mix(in srgb, var(--bg) 85%, transparent); color: var(--ink); font-size: 12px; }
  .twin-fallback { border: 1px dashed var(--line-strong); border-radius: 7px; padding: 18px; color: var(--muted-strong); display: grid; gap: 6px; justify-items: start; }
  .twin-fallback strong { color: var(--ink); }
  .twin-fallback p { margin: 0; font-size: 12px; line-height: 1.5; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
  @media (max-width: 560px) {
    .twin-card { top: auto; bottom: 8px; right: 8px; left: 8px; width: auto; }
  }
</style>
