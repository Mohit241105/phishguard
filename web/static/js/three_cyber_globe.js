/**
 * Three.js 3D Cyber Threat Shield Visualizer for PhishGuard AI
 * Rendered in WebGL
 */

window.CyberVisualizer = (function() {
  let scene, camera, renderer, particles, shieldMesh, ringMesh;
  let mouseX = 0, mouseY = 0;
  let isScanning = false;

  function init(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const width = container.clientWidth || 340;
    const height = container.clientHeight || 260;

    // Scene
    scene = new THREE.Scene();

    // Camera
    camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 15;

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    container.appendChild(renderer.domElement);

    // 1. Central Geodesic Cyber Shield / Sphere Core
    const shieldGeo = new THREE.IcosahedronGeometry(3.5, 2);
    const shieldMat = new THREE.MeshBasicMaterial({
      color: 0x3b82f6,
      wireframe: true,
      transparent: true,
      opacity: 0.6
    });
    shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    scene.add(shieldMesh);

    // 2. Rotating Cyber Ring
    const ringGeo = new THREE.TorusGeometry(5, 0.05, 16, 100);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.8
    });
    ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 3;
    scene.add(ringMesh);

    // 3. Particle Field
    const particleCount = 200;
    const particlesGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 20;
      positions[i + 1] = (Math.random() - 0.5) * 20;
      positions[i + 2] = (Math.random() - 0.5) * 20;
    }

    particlesGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const particlesMat = new THREE.PointsMaterial({
      color: 0x3b82f6,
      size: 0.15,
      transparent: true,
      opacity: 0.7
    });

    particles = new THREE.Points(particlesGeo, particlesMat);
    scene.add(particles);

    // Mouse Interaction
    container.addEventListener('mousemove', onMouseMove);

    // Window Resize
    window.addEventListener('resize', () => {
      if (!container) return;
      const newW = container.clientWidth;
      const newH = container.clientHeight;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    });

    animate();
  }

  function onMouseMove(event) {
    mouseX = (event.clientX / window.innerWidth) - 0.5;
    mouseY = (event.clientY / window.innerHeight) - 0.5;
  }

  function animate() {
    requestAnimationFrame(animate);

    if (shieldMesh) {
      shieldMesh.rotation.y += isScanning ? 0.04 : 0.005;
      shieldMesh.rotation.x += isScanning ? 0.02 : 0.002;
    }

    if (ringMesh) {
      ringMesh.rotation.z += isScanning ? 0.05 : 0.01;
    }

    if (particles) {
      particles.rotation.y += 0.001;
    }

    // Parallax
    if (scene) {
      scene.rotation.y += (mouseX * 0.5 - scene.rotation.y) * 0.05;
      scene.rotation.x += (mouseY * 0.5 - scene.rotation.x) * 0.05;
    }

    renderer.render(scene, camera);
  }

  function triggerScanAnimation(scanningState) {
    isScanning = scanningState;
    if (shieldMesh) {
      shieldMesh.material.color.setHex(scanningState ? 0x06b6d4 : 0x3b82f6);
    }
  }

  return {
    init: init,
    triggerScan: triggerScanAnimation
  };
})();
