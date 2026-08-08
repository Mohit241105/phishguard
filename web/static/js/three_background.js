/**
 * Three.js 3D WebGL Interactive Cyber Background
 */
(function() {
    const canvas = document.getElementById('three-canvas');
    if (!canvas || typeof THREE === 'undefined') return;

    const scene = new THREE.Scene();
    
    const camera = new THREE.PerspectiveCamera(
        60,
        window.innerWidth / window.innerHeight,
        0.1,
        1000
    );
    camera.position.z = 400;

    const renderer = new THREE.WebGLRenderer({
        canvas: canvas,
        alpha: true,
        antialias: true
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Particle Matrix Geometry
    const particleCount = 1200;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const colorChoices = [
        new THREE.Color('#00F2FE'),
        new THREE.Color('#4FACFE'),
        new THREE.Color('#7F00FF'),
        new THREE.Color('#00E676')
    ];

    for (let i = 0; i < particleCount; i++) {
        positions[i * 3] = (Math.random() - 0.5) * 800;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 800;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 800;

        const color = colorChoices[Math.floor(Math.random() * colorChoices.length)];
        colors[i * 3] = color.r;
        colors[i * 3 + 1] = color.g;
        colors[i * 3 + 2] = color.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 2.5,
        vertexColors: true,
        transparent: true,
        opacity: 0.75
    });

    const particleSystem = new THREE.Points(geometry, material);
    scene.add(particleSystem);

    # Adding a glowing central 3D wireframe sphere (Cyber Globe)
    const sphereGeo = new THREE.IcosahedronGeometry(120, 2);
    const sphereMat = new THREE.MeshBasicMaterial({
        color: 0x00f2fe,
        wireframe: true,
        transparent: true,
        opacity: 0.15
    });
    const cyberGlobe = new THREE.Mesh(sphereGeo, sphereMat);
    scene.add(cyberGlobe);

    // Mouse Parallax Effect
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    window.addEventListener('mousemove', (e) => {
        mouseX = (e.clientX - window.innerWidth / 2) * 0.05;
        mouseY = (e.clientY - window.innerHeight / 2) * 0.05;
    });

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });

    // Animation Loop
    function animate() {
        requestAnimationFrame(animate);

        targetX += (mouseX - targetX) * 0.05;
        targetY += (mouseY - targetY) * 0.05;

        particleSystem.rotation.y += 0.0008;
        particleSystem.rotation.x += 0.0004;

        cyberGlobe.rotation.y -= 0.0012;
        cyberGlobe.rotation.z += 0.0006;

        camera.position.x = targetX;
        camera.position.y = -targetY;
        camera.lookAt(scene.position);

        renderer.render(scene, camera);
    }

    animate();
})();
