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
  import { heatColor, riskBadge, riskFromPresence } from '../twin/heat';
  import {
    boxAround,
    contactShadow,
    framePose,
    lerpPose,
    PHI_MAX,
    PHI_MIN,
    presetPose,
    RADIUS_MAX,
    RADIUS_MIN,
    sceneBox,
    tweenProgress,
    wallFadeOpacity,
    wallRoughness,
    unitHash,
    type CameraPose,
    type CameraPresetName
  } from '../twin/twinCamera';
  import { buildPinCard, formatArea, type PinCard, type TwinDeviceInfo } from '../twin/twinCard';
  import { readTwinPalette, type TwinPalette } from '../twin/twinPalette';
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

  interface RoomHover { id: string; name: string; area: string; x: number; y: number }

  let mode = $state<'pending' | '3d' | 'fallback'>('pending');
  let selected = $state<string | null>(null);
  let selectedRoomId = $state<string | null>(null);
  let hoverRoom = $state<RoomHover | null>(null);
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
  let pinNodes = new Map<string, { pin: THREE.Mesh; ring: THREE.Mesh; hit: THREE.Mesh; floor_id: string }>();
  let roomNodes = new Map<string, { mesh: THREE.Mesh; material: THREE.MeshStandardMaterial; floor_id: string; name: string; area_m2: number | undefined; polygon: Vec2[]; elevation: number }>();
  let wallNodes: { material: THREE.MeshStandardMaterial; center: Vec2; floor_id: string }[] = [];
  // Slabs/ceilings per floor, so floors above the one being inspected can ghost.
  let ghostables: { floor_id: string; material: THREE.Material; opacity: number; transparent: boolean; depthWrite: boolean }[] = [];
  let floorGhost = new Map<string, number>();
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
  let lastPlan: HomePlan | null | undefined;
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

  function updateWallFade() {
    if (wallNodes.length === 0) return;
    const toCamera = { x: Math.cos(theta), y: Math.sin(theta) };
    const at = { x: target.x, y: target.z };
    for (const node of wallNodes) {
      let opacity = wallFadeOpacity(node.center, at, toCamera, phi) * (floorGhost.get(node.floor_id) ?? 1);
      // Snap near-solid to exactly 1 so the same camera always renders the same pixels
      // (the canvas is alpha-composited, so a 0.998 wall would differ from a 1.0 wall).
      if (opacity >= 0.995) opacity = 1;
      if (node.material.opacity !== opacity) {
        node.material.opacity = opacity;
        node.material.transparent = opacity < 1;
        node.material.depthWrite = opacity > 0.95;
      }
    }
  }

  function applyCamera() {
    if (!camera) return;
    camera.position.set(
      target.x + radius * Math.sin(phi) * Math.cos(theta),
      target.y + radius * Math.cos(phi),
      target.z + radius * Math.sin(phi) * Math.sin(theta)
    );
    camera.lookAt(target);
    updateWallFade();
  }

  function renderFrame() {
    if (renderer && scene && camera) renderer.render(scene, camera);
  }

  function requestRender() {
    // Without a loop (reduced motion, hidden panel) changes render exactly
    // once; with a loop they mark the next frame dirty.
    dirty = true;
    if (!rafHandle && mode === '3d') {
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
        node.pin.scale.setScalar(selected === id ? 1.35 : 1);
      } else {
        node.pin.scale.setScalar((selected === id ? 1.35 : 1) * (1 + 0.35 * Math.sin(Math.PI * k)));
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
    moveTo(presetPose(name, sceneDesc, aspect()), instant);
  }

  function resetView(instant = true) {
    tween = null;
    resetCount += 1;
    goPreset('iso', instant);
  }

  function floorElevation(floor_id: string): number {
    return sceneDesc.floors.find((floor) => floor.floor_id === floor_id)?.elevation_m ?? 0;
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
    const whole = sceneBox(sceneDesc);
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
    if (!dragging) {
      hoverAt(event);
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
    if (hoverRoom) hoverRoom = null;
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

  function floorVisible(floor_id: string): boolean {
    return isolatedFloorId === null || isolatedFloorId === floor_id;
  }

  function pickPin(): string | null {
    const hits = raycaster.intersectObjects(
      [...pinNodes.values()].filter((node) => floorVisible(node.floor_id)).map((node) => node.hit),
      false
    );
    const hit = hits.find((candidate) => typeof candidate.object.userData.device_id === 'string');
    return hit ? (hit.object.userData.device_id as string) : null;
  }

  function pickRoom(): string | null {
    const hits = raycaster.intersectObjects(
      [...roomNodes.values()].filter((node) => floorVisible(node.floor_id)).map((node) => node.mesh),
      false
    );
    const hit = hits.find((candidate) => typeof candidate.object.userData.room_id === 'string');
    return hit ? (hit.object.userData.room_id as string) : null;
  }

  function hoverAt(event: PointerEvent) {
    if (roomNodes.size === 0 || !pointerRay(event)) return;
    const roomId = pickRoom();
    if (roomId === null) {
      if (hoverRoom) hoverRoom = null;
      return;
    }
    const node = roomNodes.get(roomId)!;
    const rect = stage?.getBoundingClientRect();
    hoverRoom = {
      id: roomId,
      name: node.name,
      area: formatArea(node.area_m2),
      x: event.clientX - (rect?.left ?? 0),
      y: event.clientY - (rect?.top ?? 0)
    };
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

  function rebuildStatic(desc: SceneDescription) {
    if (!scene) return;
    if (staticRoot) {
      scene.remove(staticRoot);
      disposeObject(staticRoot);
    }
    shadowTexture?.dispose();
    shadowTexture = makeShadowTexture();
    floorNodes = new Map();
    pinNodes = new Map();
    roomNodes = new Map();
    wallNodes = [];
    ghostables = [];
    hoverRoom = null;
    staticRoot = new THREE.Group();
    for (const floor of desc.floors) {
      const group = new THREE.Group();
      group.position.y = floor.elevation_m;
      const walls = new THREE.Group();
      for (const slab of floor.slabs) {
        if (slab.kind === 'extent') {
          // A real slab: a thin box whose top face is the walking surface.
          const { minX, minY, maxX, maxY } = slabBounds(slab);
          const mesh = new THREE.Mesh(
            new THREE.BoxGeometry(maxX - minX, SLAB_THICKNESS_M, maxY - minY),
            new THREE.MeshStandardMaterial({ color: slab.color, roughness: 0.92, metalness: 0 })
          );
          ghostables.push({ floor_id: floor.floor_id, material: mesh.material as THREE.Material, opacity: 1, transparent: false, depthWrite: true });
          mesh.position.set((minX + maxX) / 2, -SLAB_THICKNESS_M / 2, (minY + maxY) / 2);
          group.add(mesh);
          continue;
        }
        const geometry = polygonGeometry(slab.polygon);
        if (!geometry) continue;
        const material = new THREE.MeshStandardMaterial({
          color: slab.color,
          roughness: 0.78,
          metalness: 0,
          emissive: palette.highlight,
          emissiveIntensity: 0,
          side: THREE.DoubleSide
        });
        const mesh = new THREE.Mesh(geometry, material);
        ghostables.push({ floor_id: floor.floor_id, material, opacity: 1, transparent: false, depthWrite: true });
        mesh.position.y = 0.012;
        if (slab.room_id) {
          mesh.userData.room_id = slab.room_id;
          roomNodes.set(slab.room_id, {
            mesh,
            material,
            floor_id: floor.floor_id,
            name: slab.name?.trim() ? slab.name : 'Unnamed room',
            area_m2: slab.area_m2,
            polygon: slab.polygon,
            elevation: floor.elevation_m
          });
        }
        group.add(mesh);
      }
      if (floor.ceiling) {
        const { minX, minY, maxX, maxY } = slabBounds(floor.ceiling);
        const plane = new THREE.Mesh(
          new THREE.PlaneGeometry(maxX - minX, maxY - minY),
          new THREE.MeshBasicMaterial({
            color: palette.fill,
            transparent: true,
            opacity: 0.07,
            side: THREE.DoubleSide,
            depthWrite: false
          })
        );
        ghostables.push({ floor_id: floor.floor_id, material: plane.material as THREE.Material, opacity: 0.07, transparent: true, depthWrite: false });
        plane.rotation.x = Math.PI / 2;
        plane.position.set((minX + maxX) / 2, floor.ceiling_m, (minY + maxY) / 2);
        walls.add(plane); // hidden with the walls
      }
      for (const box of floor.walls) {
        const tone = new THREE.Color(box.color);
        tone.offsetHSL(0, 0, 0.03 + (unitHash(box.wall_id) - 0.5) * 0.07);
        const material = new THREE.MeshStandardMaterial({
          color: tone,
          roughness: wallRoughness(box.wall_id),
          metalness: 0.02
        });
        const mesh = new THREE.Mesh(
          new THREE.BoxGeometry(box.length_m, box.height_m, box.thickness_m),
          material
        );
        mesh.position.set(box.center.x, box.base_m + box.height_m / 2, box.center.y);
        mesh.rotation.y = -box.angle_rad;
        walls.add(mesh);
        wallNodes.push({ material, center: box.center, floor_id: floor.floor_id });
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
          new THREE.MeshBasicMaterial({
            color: '#000000',
            map: shadowTexture,
            transparent: true,
            opacity: blob.opacity,
            depthWrite: false
          })
        );
        shadow.rotation.x = -Math.PI / 2;
        shadow.position.set(pin.position.x, 0.024, pin.position.y);
        shadow.renderOrder = 1;
        group.add(shadow);
        const mesh = new THREE.Mesh(
          new THREE.SphereGeometry(0.14, 16, 12),
          // Neutral at build time; the live-state effect applies heat colors.
          new THREE.MeshBasicMaterial({ color: heatColor(null) })
        );
        mesh.position.set(pin.position.x, pin.height_m, pin.position.y);
        mesh.userData.device_id = pin.device_id;
        // A generous invisible target keeps small pins easy to click.
        const hit = new THREE.Mesh(
          new THREE.SphereGeometry(0.32, 8, 6),
          new THREE.MeshBasicMaterial({ visible: false })
        );
        hit.position.copy(mesh.position);
        hit.userData.device_id = pin.device_id;
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(0.2, 0.27, 24),
          new THREE.MeshBasicMaterial({ color: palette.key, side: THREE.DoubleSide })
        );
        ring.geometry.rotateX(-Math.PI / 2);
        ring.position.set(pin.position.x, pin.height_m - 0.05, pin.position.y);
        ring.visible = false;
        group.add(mesh, ring, hit);
        pinNodes.set(pin.device_id, { pin: mesh, ring, hit, floor_id: floor.floor_id });
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
      staticRoot.add(group);
      floorNodes.set(floor.floor_id, { group, walls });
    }
    scene.add(staticRoot);
    applyVisibility();
    applyRoomHighlight();
    applyGhost();
    rebuildCount += 1;
  }

  function applyVisibility() {
    for (const [floor_id, node] of floorNodes) {
      node.group.visible = isolatedFloorId === null || isolatedFloorId === floor_id;
      node.walls.visible = !wallsHidden;
    }
  }

  /** Floors above the one holding the selection ghost out so they never hide it. */
  function applyGhost() {
    floorGhost = new Map();
    const focusId = selected
      ? allPins.find((pin) => pin.device_id === selected)?.floor_id
      : selectedRoomId
        ? roomNodes.get(selectedRoomId)?.floor_id
        : undefined;
    const focusLevel = sceneDesc.floors.find((floor) => floor.floor_id === focusId)?.level;
    if (focusLevel !== undefined) {
      for (const floor of sceneDesc.floors) if (floor.level > focusLevel) floorGhost.set(floor.floor_id, 0.1);
    }
    for (const entry of ghostables) {
      const factor = floorGhost.get(entry.floor_id) ?? 1;
      entry.material.opacity = entry.opacity * factor;
      entry.material.transparent = entry.transparent || factor < 1;
      entry.material.depthWrite = factor < 1 ? false : entry.depthWrite;
      entry.material.needsUpdate = true;
    }
    updateWallFade();
  }

  function applyRoomHighlight() {
    for (const [id, node] of roomNodes) {
      node.material.emissiveIntensity = hoverRoom?.id === id ? 0.38 : selectedRoomId === id ? 0.3 : 0;
    }
  }

  function updatePins(now: number) {
    for (const pin of allPins) {
      const node = pinNodes.get(pin.device_id);
      const state = presence[pin.device_id] ?? 'unknown';
      const previous = prevPresence.get(pin.device_id);
      if (previous !== undefined && previous !== state && !reduced) { pulses.set(pin.device_id, now); dirty = true; }
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
    palette = readTwinPalette();
    scene = new THREE.Scene();
    // Cool ambient from below-left, warm key from the camera's right: faces
    // the default view sees get the warm side, shaded faces stay cool.
    scene.add(new THREE.HemisphereLight(palette.ambient, palette.ground, 1.5));
    const key = new THREE.DirectionalLight(new THREE.Color(palette.key).lerp(new THREE.Color('#ffffff'), 0.3), 4.2);
    key.position.set(9, 14, -5);
    scene.add(key);
    const fill = new THREE.DirectionalLight(palette.fill, 0.8);
    fill.position.set(-8, 6, 10);
    scene.add(fill);
    camera = new THREE.PerspectiveCamera(50, 4 / 3, 0.1, 500);
    mode = '3d';
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
      window.removeEventListener('resize', resize);
      resizeObserver?.disconnect();
      resizeObserver = null;
      if (staticRoot) disposeObject(staticRoot);
      shadowTexture?.dispose();
      shadowTexture = null;
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
      if (currentPlan !== lastPlan) {
        // A new plan is a new home: start the camera from its bounds.
        lastPlan = currentPlan;
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
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void hoverRoom?.id;
    void selectedRoomId;
    applyGhost();
    applyRoomHighlight();
    requestRender();
  });

  $effect(() => {
    if (mode !== '3d') return;
    void presence;
    void bandwidth;
    void selected;
    applyGhost();
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
  <div class="twin-viewport" class:stage-hidden={mode !== '3d'}>
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
      onpointerleave={onPointerLeave}
      onwheel={onWheel}
      onkeydown={onKeyDown}
    >
      <canvas bind:this={canvas}></canvas>
    </div>
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
    {#if mode === '3d' && card}
      <aside class="twin-card" aria-label="Device details" data-device-id={card.device_id}>
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
  .twin-fallback { border: 1px dashed var(--line-strong); border-radius: 7px; padding: 18px; color: var(--muted-strong); display: grid; gap: 6px; justify-items: start; }
  .twin-fallback strong { color: var(--ink); }
  .twin-fallback p { margin: 0; font-size: 12px; line-height: 1.5; }
  .visually-hidden { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
  @media (max-width: 560px) {
    .twin-card { top: auto; bottom: 8px; right: 8px; left: 8px; width: auto; }
  }
</style>
