import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Float } from '@react-three/drei';
import * as THREE from 'three';

// Vivid neon color definitions
const COLOR_CYAN = new THREE.Color('#00e5ff');
const COLOR_AMBER = new THREE.Color('#ffab00');
const COLOR_CRIMSON = new THREE.Color('#ff1744');
const COLOR_CRIMSON_DEEP = new THREE.Color('#d50000');
const COLOR_CYAN_DEEP = new THREE.Color('#0091ea');

function ShieldModel({ isAlert, isInspecting }) {
  const outerSphereRef = useRef();
  const innerCoreRef = useRef();
  const ring1Ref = useRef();
  const ring2Ref = useRef();
  const ring3Ref = useRef();
  const haloRingRef = useRef();
  const pointsRef = useRef();

  // Smooth color transition refs
  const targetColor = useMemo(() => new THREE.Color('#00e5ff'), []);
  const currentColor = useMemo(() => new THREE.Color('#00e5ff'), []);
  const pointsColor = useMemo(() => new THREE.Color('#00e5ff'), []);

  // Track shockwave state for alert entry
  const shockwave = useRef({ active: false, progress: 0, prevAlert: false });

  useFrame((state, delta) => {
    const time = state.clock.getElapsedTime();

    // Detect alert edge (transition INTO alert)
    if (isAlert && !shockwave.current.prevAlert) {
      shockwave.current.active = true;
      shockwave.current.progress = 0;
    }
    shockwave.current.prevAlert = isAlert;

    // Advance shockwave
    let shockScale = 1.0;
    if (shockwave.current.active) {
      shockwave.current.progress += delta * 3.0;
      if (shockwave.current.progress < 1.0) {
        // Rapid expand then contract — peaks at 1.15x
        shockScale = 1.0 + 0.18 * Math.sin(shockwave.current.progress * Math.PI);
      } else {
        shockwave.current.active = false;
        shockScale = 1.0;
      }
    }

    // 1. Determine active color and animation parameters
    let rotSpeed, pulseFreq, pulseAmp, lerpSpeed, emissiveIntensity, coreOpacity;

    if (isAlert) {
      targetColor.copy(COLOR_CRIMSON);
      rotSpeed = 5.0;
      pulseFreq = 16.0;
      pulseAmp = 0.12;
      lerpSpeed = 0.18;        // Fast snap INTO crimson
      emissiveIntensity = 2.8;
      coreOpacity = 0.7;
    } else if (isInspecting) {
      targetColor.copy(COLOR_AMBER);
      rotSpeed = 2.5;
      pulseFreq = 7.0;
      pulseAmp = 0.06;
      lerpSpeed = 0.1;
      emissiveIntensity = 1.2;
      coreOpacity = 0.4;
    } else {
      targetColor.copy(COLOR_CYAN);
      rotSpeed = 0.6;
      pulseFreq = 2.0;
      pulseAmp = 0.03;
      lerpSpeed = 0.04;        // Slow graceful settle back to cyan
      emissiveIntensity = 0.7;
      coreOpacity = 0.25;
    }

    // Asymmetric color transition — snaps fast on alert, settles slowly back
    currentColor.lerp(targetColor, lerpSpeed);
    pointsColor.lerp(targetColor, lerpSpeed * 1.2);

    const pulse = 1.0 + Math.sin(time * pulseFreq) * pulseAmp;
    const totalScale = pulse * shockScale;

    // 2. Animate Outer Geodesic Wireframe Sphere
    if (outerSphereRef.current) {
      outerSphereRef.current.rotation.y += delta * rotSpeed;
      outerSphereRef.current.rotation.x += delta * (rotSpeed * 0.4);
      outerSphereRef.current.scale.set(totalScale, totalScale, totalScale);
      if (outerSphereRef.current.material) {
        outerSphereRef.current.material.color.copy(currentColor);
        outerSphereRef.current.material.emissive.copy(currentColor);
        outerSphereRef.current.material.emissiveIntensity = emissiveIntensity;
        outerSphereRef.current.material.opacity = isAlert ? 0.95 : 0.85;
      }
    }

    // 3. Animate Inner Pulsing Core — "reactor" fill effect on alert
    if (innerCoreRef.current) {
      innerCoreRef.current.rotation.y -= delta * (rotSpeed * 0.8);
      innerCoreRef.current.rotation.z += delta * (rotSpeed * 0.5);
      const innerPulse = (isAlert ? 0.95 : 0.85) + Math.sin(time * pulseFreq * 1.5) * (pulseAmp * 1.8);
      const innerScale = innerPulse * shockScale;
      innerCoreRef.current.scale.set(innerScale, innerScale, innerScale);
      if (innerCoreRef.current.material) {
        innerCoreRef.current.material.color.copy(currentColor);
        const targetOpacity = coreOpacity;
        innerCoreRef.current.material.opacity += (targetOpacity - innerCoreRef.current.material.opacity) * 0.08;
      }
    }

    // 4. Animate Multi-axis Orbital Rings
    if (ring1Ref.current) {
      ring1Ref.current.rotation.z += delta * (rotSpeed * 0.9);
      ring1Ref.current.rotation.x += delta * (rotSpeed * 0.3);
      if (ring1Ref.current.material) {
        ring1Ref.current.material.color.copy(currentColor);
        ring1Ref.current.material.opacity = isAlert ? 0.85 : 0.6;
      }
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.x -= delta * (rotSpeed * 0.7);
      ring2Ref.current.rotation.y += delta * (rotSpeed * 0.4);
      if (ring2Ref.current.material) {
        ring2Ref.current.material.color.copy(currentColor);
        ring2Ref.current.material.opacity = isAlert ? 0.75 : 0.5;
      }
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.y += delta * (rotSpeed * 0.5);
      ring3Ref.current.rotation.z -= delta * (rotSpeed * 0.8);
      if (ring3Ref.current.material) {
        ring3Ref.current.material.color.copy(currentColor);
        ring3Ref.current.material.opacity = isAlert ? 0.7 : 0.4;
      }
    }

    // 5. Animate Halo Ring — expands and glows on alert
    if (haloRingRef.current) {
      haloRingRef.current.rotation.z += delta * 0.3;
      if (haloRingRef.current.material) {
        haloRingRef.current.material.color.copy(currentColor);
        const haloTarget = isAlert ? 0.65 : isInspecting ? 0.35 : 0.15;
        haloRingRef.current.material.opacity += (haloTarget - haloRingRef.current.material.opacity) * 0.06;
      }
      const haloScale = isAlert ? 1.08 + Math.sin(time * 8) * 0.04 : 1.0;
      haloRingRef.current.scale.set(haloScale, haloScale, haloScale);
    }

    // 6. Animate floating defense node particle colors via useFrame
    if (pointsRef.current && pointsRef.current.material) {
      pointsRef.current.material.color.copy(pointsColor);
      pointsRef.current.material.size = isAlert ? 0.12 : isInspecting ? 0.1 : 0.08;
    }
  });

  return (
    <group>
      {/* Outer Geodesic Wireframe Sphere */}
      <mesh ref={outerSphereRef}>
        <icosahedronGeometry args={[2.0, 3]} />
        <meshStandardMaterial
          wireframe
          transparent
          opacity={0.85}
          roughness={0.15}
          metalness={0.9}
        />
      </mesh>

      {/* Inner Crystalline Energy Core — fills on alert */}
      <mesh ref={innerCoreRef}>
        <icosahedronGeometry args={[1.2, 1]} />
        <meshBasicMaterial
          transparent
          opacity={0.25}
          wireframe={false}
        />
      </mesh>

      {/* Orbital Ring 1 */}
      <mesh ref={ring1Ref} rotation={[Math.PI / 4, 0, 0]}>
        <torusGeometry args={[2.4, 0.025, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.6} />
      </mesh>

      {/* Orbital Ring 2 */}
      <mesh ref={ring2Ref} rotation={[0, Math.PI / 3, Math.PI / 6]}>
        <torusGeometry args={[2.6, 0.02, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.5} />
      </mesh>

      {/* Orbital Ring 3 */}
      <mesh ref={ring3Ref} rotation={[-Math.PI / 5, Math.PI / 4, 0]}>
        <torusGeometry args={[2.8, 0.018, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.4} />
      </mesh>

      {/* Alert Halo Ring — outer warning glow that expands during quarantine */}
      <mesh ref={haloRingRef} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[3.2, 0.04, 16, 120]} />
        <meshBasicMaterial transparent opacity={0.15} />
      </mesh>

      {/* Floating Defense Node Vertices — animated via useFrame */}
      <points ref={pointsRef}>
        <icosahedronGeometry args={[2.02, 2]} />
        <pointsMaterial
          size={0.08}
          transparent
          opacity={0.9}
          sizeAttenuation
        />
      </points>
    </group>
  );
}

export default function CyberShield({ isAlert = false, isInspecting = false }) {
  return (
    <div className="relative w-full h-[360px] min-h-[360px] max-h-[360px] overflow-hidden flex items-center justify-center select-none">
      {/* Background radial glow matching current status — intensified for alert */}
      <div
        className={`absolute inset-0 transition-all duration-500 pointer-events-none ${
          isAlert
            ? 'opacity-100 bg-[radial-gradient(ellipse_at_center,rgba(255,23,68,0.4)_0%,rgba(213,0,0,0.15)_40%,transparent_70%)]'
            : isInspecting
            ? 'opacity-80 bg-[radial-gradient(ellipse_at_center,rgba(255,171,0,0.25)_0%,transparent_70%)]'
            : 'opacity-50 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.2)_0%,transparent_70%)]'
        }`}
      />

      {/* Secondary pulsing vignette ring on alert */}
      {isAlert && (
        <div className="absolute inset-0 pointer-events-none animate-shield-pulse bg-[radial-gradient(ellipse_at_center,transparent_30%,rgba(255,23,68,0.12)_60%,rgba(213,0,0,0.25)_100%)]" />
      )}

      <Canvas
        camera={{ position: [0, 0, 6.2], fov: 45 }}
        style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0 }}
        dpr={[1, 2]}
      >
        <ambientLight intensity={isAlert ? 1.2 : 0.5} />
        <pointLight
          position={[10, 10, 10]}
          intensity={isAlert ? 3.5 : 1.2}
          color={isAlert ? '#ff1744' : isInspecting ? '#ffab00' : '#00e5ff'}
        />
        <pointLight
          position={[-10, -10, -10]}
          intensity={isAlert ? 1.8 : 0.8}
          color={isAlert ? '#d50000' : '#0091ea'}
        />
        {/* Extra fill light on alert for maximum bloom */}
        {isAlert && (
          <pointLight
            position={[0, 0, 5]}
            intensity={2.0}
            color="#ff1744"
            distance={12}
          />
        )}

        <Float speed={1.5} rotationIntensity={0.3} floatIntensity={0.4}>
          <ShieldModel isAlert={isAlert} isInspecting={isInspecting} />
        </Float>

        <OrbitControls
          enableZoom={false}
          enablePan={false}
          rotateSpeed={0.6}
          minPolarAngle={Math.PI / 4}
          maxPolarAngle={Math.PI - Math.PI / 4}
        />
      </Canvas>

      {/* Interactive Drag Hint */}
      <div className="absolute bottom-3 left-1/2 -translate-x-1/2 text-[10px] uppercase tracking-widest text-slate-500 font-mono pointer-events-none flex items-center gap-1.5 opacity-60">
        <span>Click &amp; Drag to Rotate Shield</span>
      </div>
    </div>
  );
}
