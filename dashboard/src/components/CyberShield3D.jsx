import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Float } from '@react-three/drei';
import * as THREE from 'three';

// Color definitions
const COLOR_CYAN = new THREE.Color('#38bdf8');
const COLOR_AMBER = new THREE.Color('#f59e0b');
const COLOR_CRIMSON = new THREE.Color('#ef4444');

function ShieldModel({ isAlert, isInspecting }) {
  const outerSphereRef = useRef();
  const innerCoreRef = useRef();
  const ring1Ref = useRef();
  const ring2Ref = useRef();
  const ring3Ref = useRef();

  // Target color reference for smooth lerping
  const targetColor = useMemo(() => new THREE.Color(), []);
  const currentColor = useMemo(() => new THREE.Color('#38bdf8'), []);

  useFrame((state, delta) => {
    // 1. Determine active color and speed based on props
    let rotSpeed = 0.6;
    let pulseFreq = 2.0;
    let pulseAmp = 0.03;

    if (isAlert) {
      targetColor.copy(COLOR_CRIMSON);
      rotSpeed = 4.2;
      pulseFreq = 14.0;
      pulseAmp = 0.09;
    } else if (isInspecting) {
      targetColor.copy(COLOR_AMBER);
      rotSpeed = 2.2;
      pulseFreq = 6.0;
      pulseAmp = 0.05;
    } else {
      targetColor.copy(COLOR_CYAN);
      rotSpeed = 0.6;
      pulseFreq = 2.0;
      pulseAmp = 0.03;
    }

    // Smooth color transition
    currentColor.lerp(targetColor, 0.1);

    const time = state.clock.getElapsedTime();
    const pulse = 1.0 + Math.sin(time * pulseFreq) * pulseAmp;

    // 2. Animate Outer Geodesic Wireframe Sphere
    if (outerSphereRef.current) {
      outerSphereRef.current.rotation.y += delta * rotSpeed;
      outerSphereRef.current.rotation.x += delta * (rotSpeed * 0.4);
      outerSphereRef.current.scale.set(pulse, pulse, pulse);
      if (outerSphereRef.current.material) {
        outerSphereRef.current.material.color.copy(currentColor);
        outerSphereRef.current.material.emissive.copy(currentColor);
        outerSphereRef.current.material.emissiveIntensity = isAlert ? 1.4 : isInspecting ? 0.9 : 0.6;
      }
    }

    // 3. Animate Inner Pulsing Core
    if (innerCoreRef.current) {
      innerCoreRef.current.rotation.y -= delta * (rotSpeed * 0.8);
      innerCoreRef.current.rotation.z += delta * (rotSpeed * 0.5);
      const innerPulse = 0.85 + Math.sin(time * pulseFreq * 1.5) * (pulseAmp * 1.5);
      innerCoreRef.current.scale.set(innerPulse, innerPulse, innerPulse);
      if (innerCoreRef.current.material) {
        innerCoreRef.current.material.color.copy(currentColor);
      }
    }

    // 4. Animate Multi-axis Orbital Rings
    if (ring1Ref.current) {
      ring1Ref.current.rotation.z += delta * (rotSpeed * 0.9);
      ring1Ref.current.rotation.x += delta * (rotSpeed * 0.3);
      if (ring1Ref.current.material) ring1Ref.current.material.color.copy(currentColor);
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.x -= delta * (rotSpeed * 0.7);
      ring2Ref.current.rotation.y += delta * (rotSpeed * 0.4);
      if (ring2Ref.current.material) ring2Ref.current.material.color.copy(currentColor);
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.y += delta * (rotSpeed * 0.5);
      ring3Ref.current.rotation.z -= delta * (rotSpeed * 0.8);
      if (ring3Ref.current.material) ring3Ref.current.material.color.copy(currentColor);
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
          roughness={0.2}
          metalness={0.8}
        />
      </mesh>

      {/* Inner Crystalline Energy Core */}
      <mesh ref={innerCoreRef}>
        <icosahedronGeometry args={[1.2, 1]} />
        <meshBasicMaterial
          transparent
          opacity={isAlert ? 0.45 : isInspecting ? 0.35 : 0.25}
          wireframe={false}
        />
      </mesh>

      {/* Orbital Ring 1 */}
      <mesh ref={ring1Ref} rotation={[Math.PI / 4, 0, 0]}>
        <torusGeometry args={[2.4, 0.02, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.6} />
      </mesh>

      {/* Orbital Ring 2 */}
      <mesh ref={ring2Ref} rotation={[0, Math.PI / 3, Math.PI / 6]}>
        <torusGeometry args={[2.6, 0.018, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.5} />
      </mesh>

      {/* Orbital Ring 3 */}
      <mesh ref={ring3Ref} rotation={[-Math.PI / 5, Math.PI / 4, 0]}>
        <torusGeometry args={[2.8, 0.015, 16, 80]} />
        <meshBasicMaterial transparent opacity={0.4} />
      </mesh>

      {/* Floating Defense Node Vertices */}
      <points>
        <icosahedronGeometry args={[2.02, 2]} />
        <pointsMaterial
          size={0.08}
          color={isAlert ? '#ef4444' : isInspecting ? '#f59e0b' : '#38bdf8'}
          transparent
          opacity={0.9}
        />
      </points>
    </group>
  );
}

export default function CyberShield3D({ isAlert = false, isInspecting = false }) {
  return (
    <div className="w-full h-full relative flex items-center justify-center select-none">
      {/* Background radial glow matching current status */}
      <div
        className={`absolute inset-0 transition-opacity duration-700 pointer-events-none ${
          isAlert
            ? 'opacity-80 bg-[radial-gradient(ellipse_at_center,rgba(239,68,68,0.25)_0%,transparent_70%)]'
            : isInspecting
            ? 'opacity-70 bg-[radial-gradient(ellipse_at_center,rgba(245,158,11,0.2)_0%,transparent_70%)]'
            : 'opacity-50 bg-[radial-gradient(ellipse_at_center,rgba(56,189,248,0.18)_0%,transparent_70%)]'
        }`}
      />

      <Canvas
        camera={{ position: [0, 0, 6.2], fov: 45 }}
        style={{ width: '100%', height: '100%' }}
        dpr={[1, 2]}
      >
        <ambientLight intensity={isAlert ? 0.9 : 0.5} />
        <pointLight
          position={[10, 10, 10]}
          intensity={isAlert ? 2.5 : 1.2}
          color={isAlert ? '#ef4444' : isInspecting ? '#f59e0b' : '#38bdf8'}
        />
        <pointLight
          position={[-10, -10, -10]}
          intensity={0.8}
          color={isAlert ? '#f43f5e' : '#0284c7'}
        />

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
        <span>Click & Drag to Rotate Shield</span>
      </div>
    </div>
  );
}
