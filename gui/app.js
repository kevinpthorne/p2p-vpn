// p2p-vpn P2P VPN Frontend Application Logic

// Client State
let currentTab = 'dashboard';
let profiles = [];
let activeProfileId = '';
let isConnected = false;
let logEventSource = null;
let uptimeInterval = null;
let uptimeSeconds = 0;

// Speed history for chart (last 30 seconds)
const maxChartPoints = 30;
const speedHistory = {
    down: Array(maxChartPoints).fill(0),
    up: Array(maxChartPoints).fill(0)
};

// Canvas Map Node State
let mapNodes = [];
let mapLinks = [];
let mapCenter = { x: 0, y: 0 };

// CSS variable resolution helper
let cssVarCache = {};
function getCssVar(name, fallback) {
    if (!cssVarCache[name]) {
        const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        if (val) {
            cssVarCache[name] = val;
        } else {
            return fallback;
        }
    }
    return cssVarCache[name];
}

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initProfiles();
    initPKI();
    initLogs();
    
    // Start periodic status updates
    pollStatus();
    setInterval(pollStatus, 1000);
    
    // Setup canvas resize listener
    const meshCanvas = document.getElementById('mesh-canvas');
    if (meshCanvas) {
        window.addEventListener('resize', resizeMapCanvas);
        resizeMapCanvas();
        requestAnimationFrame(animateMeshMap);
    }
});

// Tab Navigation
function initTabs() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabViews = document.querySelectorAll('.tab-view');
    
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            currentTab = tabId;
            
            navButtons.forEach(b => b.classList.remove('active'));
            tabViews.forEach(v => v.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(`view-${tabId}`).classList.add('active');
            
            if (tabId === 'dashboard') {
                resizeMapCanvas();
            }
        });
    });
}

// REST API Helpers
async function apiFetch(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(errText || response.statusText);
        }
        return await response.json();
    } catch (err) {
        console.error(`API Error (${endpoint}):`, err);
        return { error: err.message };
    }
}

// Status Polling
async function pollStatus() {
    const data = await apiFetch('/api/status');
    if (data.error) return;
    
    // Update Connection State
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const toggleInput = document.getElementById('vpn-toggle');
    const subtitle = document.getElementById('connection-subtitle');
    
    isConnected = data.connected;
    
    if (data.connected) {
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'CONNECTED';
        statusText.style.color = 'var(--accent-green)';
        subtitle.textContent = `VPN active on cluster: ${data.cluster}`;
        toggleInput.checked = true;
        
        // Handle Uptime timer
        if (!uptimeInterval) {
            uptimeSeconds = data.uptime_seconds;
            startUptimeTimer();
        }
    } else {
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'DISCONNECTED';
        statusText.style.color = 'var(--text-secondary)';
        subtitle.textContent = 'Secure, encrypted P2P tunnel interface';
        toggleInput.checked = false;
        
        stopUptimeTimer();
    }
    
    document.getElementById('local-peer-id').textContent = data.local_peer_id || 'Not Connected';
    document.getElementById('active-profile-name').textContent = data.active_profile || 'None';
    document.getElementById('vpn-ip-val').textContent = data.virtual_ip || '-';
    
    activeProfileId = data.active_profile_id || '';
    
    // Update performance stats
    updateSpeedIndicator('down-speed', data.down_speed_bps);
    updateSpeedIndicator('up-speed', data.up_speed_bps);
    
    // Push speed to history
    speedHistory.down.push(data.down_speed_bps);
    speedHistory.down.shift();
    speedHistory.up.push(data.up_speed_bps);
    speedHistory.up.shift();
    
    drawSpeedChart();
    
    // Update peers table & graph data
    updatePeersData(data);
}

// Uptime Timer
function startUptimeTimer() {
    stopUptimeTimer();
    const uptimeVal = document.getElementById('uptime-val');
    
    const format = (s) => {
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        return [h, m, sec].map(v => v.toString().padStart(2, '0')).join(':');
    };
    
    uptimeVal.textContent = format(uptimeSeconds);
    uptimeInterval = setInterval(() => {
        uptimeSeconds++;
        uptimeVal.textContent = format(uptimeSeconds);
    }, 1000);
}

function stopUptimeTimer() {
    if (uptimeInterval) {
        clearInterval(uptimeInterval);
        uptimeInterval = null;
    }
    uptimeSeconds = 0;
    document.getElementById('uptime-val').textContent = '00:00:00';
}

function updateSpeedIndicator(elementId, bps) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    if (bps < 1024) {
        el.textContent = `${bps.toFixed(0)} B/s`;
    } else if (bps < 1048576) {
        el.textContent = `${(bps / 1024).toFixed(1)} KB/s`;
    } else {
        el.textContent = `${(bps / 1048576).toFixed(1)} MB/s`;
    }
}

// VPN Toggle Listener
document.getElementById('vpn-toggle').addEventListener('change', async (e) => {
    const connect = e.target.checked;
    
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    
    if (connect) {
        if (!activeProfileId) {
            alert('Please select or configure an active profile in the Profiles tab first!');
            e.target.checked = false;
            return;
        }
        
        statusDot.className = 'status-dot connecting';
        statusText.textContent = 'CONNECTING...';
        statusText.style.color = 'var(--accent-yellow)';
        
        const res = await apiFetch('/api/connect', {
            method: 'POST',
            body: JSON.stringify({ profile_id: activeProfileId })
        });
        
        if (res.error) {
            alert(`Failed to start VPN: ${res.error}`);
            pollStatus();
        }
    } else {
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'DISCONNECTING...';
        
        const res = await apiFetch('/api/disconnect', { method: 'POST' });
        if (res.error) {
            alert(`Failed to stop VPN: ${res.error}`);
        }
        pollStatus();
    }
});

// Speed Chart canvas drawing
function drawSpeedChart() {
    const canvas = document.getElementById('speed-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    // Fit canvas bounds to wrapper CSS layout
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    const w = rect.width;
    const h = rect.height;
    ctx.clearRect(0, 0, w, h);
    
    // Find maximum speed value in the history for auto-scaling
    const maxVal = Math.max(1024, ...speedHistory.down, ...speedHistory.up);
    
    // Draw grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.03)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
        const y = (h / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }
    
    // Draw Download path
    drawSpeedLine(ctx, speedHistory.down, w, h, maxVal, 'rgba(0, 240, 255, 0.8)', 'rgba(0, 240, 255, 0.05)');
    // Draw Upload path
    drawSpeedLine(ctx, speedHistory.up, w, h, maxVal, 'rgba(189, 0, 255, 0.8)', 'rgba(189, 0, 255, 0.05)');
}

function drawSpeedLine(ctx, data, w, h, maxVal, strokeColor, fillColor) {
    const step = w / (maxChartPoints - 1);
    ctx.beginPath();
    ctx.moveTo(0, h);
    
    const getPointX = (i) => i * step;
    const getPointY = (val) => h - (val / maxVal) * (h - 20) - 5;
    
    // Draw spline curve
    ctx.lineTo(0, getPointY(data[0]));
    for (let i = 0; i < data.length - 1; i++) {
        const x1 = getPointX(i);
        const y1 = getPointY(data[i]);
        const x2 = getPointX(i + 1);
        const y2 = getPointY(data[i + 1]);
        const xc = (x1 + x2) / 2;
        const yc = (y1 + y2) / 2;
        ctx.quadraticCurveTo(x1, y1, xc, yc);
    }
    ctx.lineTo(getPointX(data.length - 1), getPointY(data[data.length - 1]));
    
    // Draw neon glow by stroking with a wider semi-transparent line first
    ctx.strokeStyle = strokeColor.replace('0.8', '0.2');
    ctx.lineWidth = 6;
    ctx.stroke();
    
    // Stroke the sharp main line
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();
    
    // Fill underneath
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.fillStyle = fillColor;
    ctx.fill();
}

// Connected Peers updates and Topology map data
function updatePeersData(statusData) {
    const tbody = document.getElementById('peers-list');
    if (!tbody) return;
    
    const endpoints = statusData.endpoints || [];
    const relays = statusData.relays || [];
    const allPeers = [...endpoints, ...relays];
    
    if (allPeers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No connected peers. Start the VPN to join the mesh.</td></tr>`;
        mapLinks = [];
        mapNodes = [];
        return;
    }
    
    // Populate list
    let html = '';
    allPeers.forEach(peer => {
        const isRelay = peer.role === 'relay';
        const roleText = isRelay ? 'Relay' : 'Endpoint';
        const roleClass = isRelay ? 'relay' : 'endpoint';
        const ipText = peer.virtual_ip || (isRelay ? 'Relay Node' : '-');
        const latencyText = peer.latency_ms >= 0 ? `${peer.latency_ms} ms` : 'N/A';
        
        html += `
            <tr>
                <td class="code-area" title="${peer.peer_id}">${peer.peer_id.slice(0, 16)}...</td>
                <td><span class="peer-role-badge ${roleClass}">${roleText}</span></td>
                <td class="code-area">${ipText}</td>
                <td><span class="peer-status-active">Active</span></td>
                <td class="code-area">${latencyText}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
    
    // Update mesh nodes & links for animation
    updateMeshTopology(statusData);
}

// Mesh topology force simulation builder
function updateMeshTopology(statusData) {
    const currentNodesMap = new Map();
    
    // Always include local node
    const localId = statusData.local_peer_id || 'local-node';
    currentNodesMap.set(localId, {
        id: localId,
        label: 'Local Node',
        ip: statusData.virtual_ip || '',
        type: 'local',
        x: mapCenter.x,
        y: mapCenter.y,
        vx: 0,
        vy: 0,
        radius: 12
    });
    
    // Add Endpoints
    const endpoints = statusData.endpoints || [];
    endpoints.forEach(ep => {
        const id = ep.peer_id;
        const exists = mapNodes.find(n => n.id === id);
        currentNodesMap.set(id, {
            id: id,
            label: id.slice(0, 8),
            ip: ep.virtual_ip,
            type: 'endpoint',
            latency: ep.latency_ms,
            // Keep existing position if node already existed to prevent flashing
            x: exists ? exists.x : mapCenter.x + (Math.random() - 0.5) * 100,
            y: exists ? exists.y : mapCenter.y + (Math.random() - 0.5) * 100,
            vx: exists ? exists.vx : 0,
            vy: exists ? exists.vy : 0,
            radius: 8
        });
    });
    
    // Add Relays
    const relays = statusData.relays || [];
    relays.forEach(r => {
        const id = r.peer_id;
        const exists = mapNodes.find(n => n.id === id);
        currentNodesMap.set(id, {
            id: id,
            label: id.slice(0, 8),
            ip: 'Relay',
            type: 'relay',
            latency: r.latency_ms,
            x: exists ? exists.x : mapCenter.x + (Math.random() - 0.5) * 100,
            y: exists ? exists.y : mapCenter.y + (Math.random() - 0.5) * 100,
            vx: exists ? exists.vx : 0,
            vy: exists ? exists.vy : 0,
            radius: 9
        });
    });
    
    // Set nodes list
    mapNodes = Array.from(currentNodesMap.values());
    
    // Rebuild links
    mapLinks = [];
    
    // Connect endpoints and relays to local node
    endpoints.forEach(ep => {
        mapLinks.push({
            source: localId,
            target: ep.peer_id,
            latency: ep.latency_ms,
            type: 'tunnel'
        });
    });
    
    relays.forEach(r => {
        mapLinks.push({
            source: localId,
            target: r.peer_id,
            latency: r.latency_ms,
            type: 'control'
        });
    });
}

function resizeMapCanvas() {
    const canvas = document.getElementById('mesh-canvas');
    if (!canvas) return;
    const parent = canvas.parentNode;
    const width = parent.clientWidth;
    const height = parent.clientHeight;
    
    const targetWidth = Math.floor(width * window.devicePixelRatio);
    const targetHeight = Math.floor(height * window.devicePixelRatio);
    
    if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
        canvas.width = targetWidth;
        canvas.height = targetHeight;
        
        mapCenter = {
            x: width / 2,
            y: height / 2
        };
        
        // Pin local node to center
        const local = mapNodes.find(n => n.type === 'local');
        if (local) {
            local.x = mapCenter.x;
            local.y = mapCenter.y;
        }
    }
}

// Animate Mesh map using simple physics loop
function animateMeshMap(timestamp) {
    // Keep canvas size synchronized dynamically
    resizeMapCanvas();

    const canvas = document.getElementById('mesh-canvas');
    if (!canvas || currentTab !== 'dashboard') {
        requestAnimationFrame(animateMeshMap);
        return;
    }
    
    const ctx = canvas.getContext('2d');
    const w = canvas.width / window.devicePixelRatio;
    const h = canvas.height / window.devicePixelRatio;
    
    // Clear entire canvas backing store to prevent trailing/smearing
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.save();
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    // 1. Apply Forces
    // Center local node
    const local = mapNodes.find(n => n.type === 'local');
    if (local) {
        local.x = mapCenter.x;
        local.y = mapCenter.y;
    }
    
    // Repulsion force between nodes
    for (let i = 0; i < mapNodes.length; i++) {
        const n1 = mapNodes[i];
        if (n1.type === 'local') continue;
        
        // Attraction force to local center node (acting like a spring)
        const dx = mapCenter.x - n1.x;
        const dy = mapCenter.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const targetDist = n1.type === 'relay' ? 120 : 160;
        
        const force = (dist - targetDist) * 0.03;
        n1.vx += (dx / dist) * force;
        n1.vy += (dy / dist) * force;
        
        // Repel from other nodes
        for (let j = 0; j < mapNodes.length; j++) {
            if (i === j) continue;
            const n2 = mapNodes[j];
            const rx = n1.x - n2.x;
            const ry = n1.y - n2.y;
            const rdist = Math.sqrt(rx * rx + ry * ry) || 1;
            
            if (rdist < 100) {
                const repForce = (100 - rdist) * 0.08;
                n1.vx += (rx / rdist) * repForce;
                n1.vy += (ry / rdist) * repForce;
            }
        }
        
        // Apply friction & boundary limits
        n1.vx *= 0.85;
        n1.vy *= 0.85;
        n1.x += n1.vx;
        n1.y += n1.vy;
        
        // Clamp bounds
        n1.x = Math.max(n1.radius + 10, Math.min(w - n1.radius - 10, n1.x));
        n1.y = Math.max(n1.radius + 10, Math.min(h - n1.radius - 10, n1.y));
    }
    
    // 2. Draw Links
    mapLinks.forEach(link => {
        const sourceNode = mapNodes.find(n => n.id === link.source);
        const targetNode = mapNodes.find(n => n.id === link.target);
        
        if (!sourceNode || !targetNode) return;
        
        // Draw line
        ctx.beginPath();
        ctx.moveTo(sourceNode.x, sourceNode.y);
        ctx.lineTo(targetNode.x, targetNode.y);
        
        if (link.type === 'tunnel') {
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.4)';
            ctx.lineWidth = 2;
            ctx.setLineDash([]);
        } else {
            ctx.strokeStyle = 'rgba(189, 0, 255, 0.4)';
            ctx.lineWidth = 1.5;
            ctx.setLineDash([4, 4]);
        }
        ctx.stroke();
        
        // Draw packet flows (moving dots)
        const t = (timestamp % 2000) / 2000;
        const px = sourceNode.x + (targetNode.x - sourceNode.x) * t;
        const py = sourceNode.y + (targetNode.y - sourceNode.y) * t;
        
        // Draw flow dot glow
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = link.type === 'tunnel' ? 'rgba(0, 240, 255, 0.25)' : 'rgba(189, 0, 255, 0.25)';
        ctx.fill();
        
        // Draw main flow dot
        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        const flowColor = link.type === 'tunnel' ? getCssVar('--accent-cyan', '#00f0ff') : getCssVar('--accent-purple', '#bd00ff');
        ctx.fillStyle = flowColor;
        ctx.fill();
        
        // Draw Latency Pill
        const midX = (sourceNode.x + targetNode.x) / 2;
        const midY = (sourceNode.y + targetNode.y) / 2;
        const latencyText = link.latency >= 0 ? `${link.latency}ms` : 'N/A';
        
        ctx.fillStyle = 'rgba(10, 12, 20, 0.85)';
        ctx.strokeStyle = link.type === 'tunnel' ? 'rgba(0, 240, 255, 0.3)' : 'rgba(189, 0, 255, 0.3)';
        ctx.lineWidth = 1;
        
        const pillW = 42;
        const pillH = 16;
        drawRoundedRect(ctx, midX - pillW/2, midY - pillH/2, pillW, pillH, 4, true, true);
        
        ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
        ctx.font = `10px ${getCssVar('--font-mono', 'monospace')}`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(latencyText, midX, midY + 1);
    });
    ctx.setLineDash([]); // reset
    
    // 3. Draw Nodes
    mapNodes.forEach(node => {
        // Pulse effects
        const pulse = 2 * Math.sin(timestamp / 300);
        
        if (node.type === 'local') {
            const localColor = getCssVar('--accent-cyan', '#00f0ff');
            
            // Soft glow behind local node
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 6 + pulse/2, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 240, 255, 0.15)';
            ctx.fill();
            
            // Inner Core
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fillStyle = localColor;
            ctx.fill();
            
            // Outer Ring
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 6 + pulse, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.3)';
            ctx.lineWidth = 1.5;
            ctx.stroke();
        } else if (node.type === 'endpoint') {
            const epColor = getCssVar('--accent-cyan', '#00f0ff');
            
            // Soft glow behind endpoint node
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 4 + pulse/2, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 240, 255, 0.12)';
            ctx.fill();
            
            // Node body
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(16, 20, 30, 0.9)';
            ctx.strokeStyle = epColor;
            ctx.lineWidth = 2.5;
            ctx.fill();
            ctx.stroke();
        } else if (node.type === 'relay') {
            const relayColor = getCssVar('--accent-purple', '#bd00ff');
            
            // Soft glow behind relay node
            ctx.save();
            ctx.translate(node.x, node.y);
            ctx.rotate(Math.PI / 4);
            ctx.beginPath();
            const glowSize = node.radius + 4 + pulse/2;
            ctx.rect(-glowSize, -glowSize, glowSize * 2, glowSize * 2);
            ctx.fillStyle = 'rgba(189, 0, 255, 0.12)';
            ctx.fill();
            ctx.restore();
            
            // Node body (Diamond)
            ctx.save();
            ctx.translate(node.x, node.y);
            ctx.rotate(Math.PI / 4);
            ctx.beginPath();
            ctx.rect(-node.radius, -node.radius, node.radius * 2, node.radius * 2);
            ctx.fillStyle = 'rgba(16, 20, 30, 0.9)';
            ctx.strokeStyle = relayColor;
            ctx.lineWidth = 2;
            ctx.fill();
            ctx.stroke();
            ctx.restore();
        }
        
        // Node labels
        ctx.fillStyle = getCssVar('--text-primary', '#f1f5f9');
        ctx.font = `bold 11px ${getCssVar('--font-sans', 'sans-serif')}`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(node.label, node.x, node.y + node.radius + 6);
        
        ctx.fillStyle = getCssVar('--text-muted', '#64748b');
        ctx.font = `10px ${getCssVar('--font-mono', 'monospace')}`;
        ctx.fillText(node.ip, node.x, node.y + node.radius + 18);
    });
    
    ctx.restore();
    requestAnimationFrame(animateMeshMap);
}

function drawRoundedRect(ctx, x, y, w, h, r, fill = true, stroke = false) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
    if (fill) ctx.fill();
    if (stroke) ctx.stroke();
}

// Profiles Management
async function initProfiles() {
    const listItems = document.getElementById('profiles-list-items');
    const editorCard = document.getElementById('profile-editor-card');
    const form = document.getElementById('profile-form');
    
    // Refresh List
    async function loadProfilesList() {
        const data = await apiFetch('/api/profiles');
        profiles = data.profiles || [];
        
        listItems.innerHTML = '';
        if (profiles.length === 0) {
            listItems.innerHTML = `<div class="empty-state">No saved profiles. Click add to configure.</div>`;
            editorCard.style.display = 'none';
            return;
        }
        
        profiles.forEach(p => {
            const isProfileActive = p.name === document.getElementById('active-profile-name').textContent;
            
            const div = document.createElement('div');
            div.className = `profile-item ${p.id === document.getElementById('edit-profile-id').value ? 'active' : ''}`;
            div.innerHTML = `
                <div class="profile-item-info">
                    <h4>${escapeHTML(p.name)}</h4>
                    <span>${p.mode} &bull; ${escapeHTML(p.cluster_id)}</span>
                </div>
                ${isProfileActive ? `<span class="profile-active-tag">Active</span>` : ''}
            `;
            div.addEventListener('click', () => editProfile(p.id));
            listItems.appendChild(div);
        });
    }
    
    function updateModeVisibility(mode) {
        const divider = document.getElementById('p-divider-vpn');
        const groupTunip = document.getElementById('p-group-tunip');
        const groupAdvertise = document.getElementById('p-group-advertise');
        const groupDatakey = document.getElementById('p-group-datakey');
        
        if (mode === 'relay') {
            if (divider) divider.style.display = 'none';
            if (groupTunip) {
                groupTunip.style.display = 'none';
                document.getElementById('p-tunip').disabled = true;
            }
            if (groupAdvertise) {
                groupAdvertise.style.display = 'none';
                document.getElementById('p-advertise').disabled = true;
            }
            if (groupDatakey) {
                groupDatakey.style.display = 'none';
                document.getElementById('p-datakey').disabled = true;
            }
        } else {
            if (divider) divider.style.display = 'block';
            if (groupTunip) {
                groupTunip.style.display = 'block';
                document.getElementById('p-tunip').disabled = false;
            }
            if (groupAdvertise) {
                groupAdvertise.style.display = 'block';
                document.getElementById('p-advertise').disabled = false;
            }
            if (groupDatakey) {
                groupDatakey.style.display = 'block';
                document.getElementById('p-datakey').disabled = false;
            }
        }
    }
    
    function editProfile(id) {
        const p = profiles.find(x => x.id === id);
        if (!p) return;
        
        // Highlight active list item
        document.querySelectorAll('.profile-item').forEach(el => el.classList.remove('active'));
        
        const activeBtn = document.getElementById('btn-activate-profile');
        if (activeBtn) {
            if (p.id === activeProfileId) {
                activeBtn.textContent = 'Active';
                activeBtn.disabled = true;
                activeBtn.className = 'btn btn-outline btn-sm';
            } else {
                activeBtn.textContent = 'Use Profile';
                activeBtn.disabled = false;
                activeBtn.className = 'btn btn-success btn-sm';
            }
        }
        
        document.getElementById('edit-profile-id').value = p.id;
        document.getElementById('editor-title').textContent = `Edit Profile: ${p.name}`;
        
        document.getElementById('p-name').value = p.name;
        document.getElementById('p-mode').value = p.mode;
        updateModeVisibility(p.mode);
        document.getElementById('p-cluster').value = p.cluster_id;
        document.getElementById('p-port').value = p.port || '';
        document.getElementById('p-dryrun').checked = p.dry_run;
        document.getElementById('p-tunip').value = p.tun_ip || '';
        document.getElementById('p-advertise').value = p.advertise || '';
        document.getElementById('p-datakey').value = p.data_key || '';
        document.getElementById('p-identity').value = p.identity_path || '';
        document.getElementById('p-ca-key').value = p.ca_key_path || '';
        document.getElementById('p-sig-content').value = p.node_sig_content || '';
        document.getElementById('p-allowed-peers').value = p.allowed_peers_path || '';
        document.getElementById('p-relays').value = p.relay_addrs ? p.relay_addrs.join('\n') : '';
        
        // Hide Peer ID display until loaded
        document.querySelector('.peer-id-display').style.display = 'none';
        
        editorCard.style.display = 'block';
        
        // Auto-refresh Peer ID info for the profile key path
        fetchIdentityPeerId();
    }
    
    // Fetch Peer ID for the active identity path
    async function fetchIdentityPeerId() {
        const path = document.getElementById('p-identity').value.trim();
        if (!path) return;
        
        const res = await apiFetch('/api/identities/info', {
            method: 'POST',
            body: JSON.stringify({ path: path })
        });
        
        const box = document.querySelector('.peer-id-display');
        const code = document.getElementById('config-peer-id');
        
        if (res.peer_id) {
            code.textContent = res.peer_id;
            box.style.display = 'flex';
        } else {
            box.style.display = 'none';
        }
    }
    
    document.getElementById('btn-refresh-peerid').addEventListener('click', fetchIdentityPeerId);
    
    document.getElementById('p-mode').addEventListener('change', (e) => {
        updateModeVisibility(e.target.value);
    });
    
    // Copy config Peer ID helper
    document.getElementById('btn-copy-config-peerid').addEventListener('click', () => {
        const code = document.getElementById('config-peer-id').textContent;
        navigator.clipboard.writeText(code);
        const btn = document.getElementById('btn-copy-config-peerid');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 1500);
    });
    
    // Generate new identity file
    document.getElementById('btn-gen-identity').addEventListener('click', async () => {
        const path = document.getElementById('p-identity').value.trim();
        if (!path) {
            alert('Please specify an Identity Key Path first!');
            return;
        }
        
        if (!confirm(`Generate a new identity key file at "${path}"? This will overwrite any existing key at that path.`)) {
            return;
        }
        
        const res = await apiFetch('/api/identities/generate', {
            method: 'POST',
            body: JSON.stringify({ path: path })
        });
        
        if (res.error) {
            alert(`Error generating identity key: ${res.error}`);
        } else {
            alert(`Identity generated successfully!`);
            fetchIdentityPeerId();
        }
    });
    
    // Generate pre-shared key GCM helper
    document.getElementById('btn-gen-datakey').addEventListener('click', () => {
        const key = generateHexKey(32);
        document.getElementById('p-datakey').value = key;
    });
    
    function generateHexKey(bytes) {
        const chars = '0123456789abcdef';
        let res = '';
        for (let i = 0; i < bytes * 2; i++) {
            res += chars[Math.floor(Math.random() * 16)];
        }
        return res;
    }
    
    // Save Form
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const id = document.getElementById('edit-profile-id').value;
        const relaysText = document.getElementById('p-relays').value;
        const relay_addrs = relaysText.split('\n')
            .map(s => s.trim())
            .filter(s => s !== '');
            
        const mode = document.getElementById('p-mode').value;
        const payload = {
            id: id,
            name: document.getElementById('p-name').value.trim(),
            mode: mode,
            cluster_id: document.getElementById('p-cluster').value.trim(),
            port: parseInt(document.getElementById('p-port').value) || 0,
            dry_run: document.getElementById('p-dryrun').checked,
            tun_ip: mode === 'relay' ? '' : document.getElementById('p-tunip').value.trim(),
            advertise: mode === 'relay' ? '' : document.getElementById('p-advertise').value.trim(),
            data_key: mode === 'relay' ? '' : document.getElementById('p-datakey').value.trim(),
            identity_path: document.getElementById('p-identity').value.trim(),
            ca_key_path: document.getElementById('p-ca-key').value.trim(),
            node_sig_content: document.getElementById('p-sig-content').value.trim(),
            allowed_peers_path: document.getElementById('p-allowed-peers').value.trim(),
            relay_addrs: relay_addrs
        };
        
        const res = await apiFetch('/api/profiles', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        
        if (res.error) {
            alert(`Error saving profile: ${res.error}`);
        } else {
            await loadProfilesList();
            editProfile(res.id);
        }
    });
    
    // New Profile Trigger
    document.getElementById('btn-new-profile').addEventListener('click', () => {
        document.getElementById('edit-profile-id').value = '';
        document.getElementById('editor-title').textContent = 'Create New Profile';
        form.reset();
        
        // Generate defaults
        document.getElementById('p-name').value = 'New Profile';
        document.getElementById('p-mode').value = 'endpoint';
        updateModeVisibility('endpoint');
        document.getElementById('p-cluster').value = 'my-vpn-cluster';
        document.getElementById('p-identity').value = 'identity-endpoint.key';
        document.getElementById('p-dryrun').checked = false;
        
        document.querySelector('.peer-id-display').style.display = 'none';
        editorCard.style.display = 'block';
    });
    
    // Delete Profile
    document.getElementById('btn-delete-profile').addEventListener('click', async () => {
        const id = document.getElementById('edit-profile-id').value;
        if (!id) return;
        
        if (!confirm('Are you sure you want to delete this profile?')) return;
        
        const res = await apiFetch(`/api/profiles?id=${id}`, {
            method: 'DELETE'
        });
        
        if (res.error) {
            alert(`Error deleting profile: ${res.error}`);
        } else {
            document.getElementById('edit-profile-id').value = '';
            editorCard.style.display = 'none';
            await loadProfilesList();
        }
    });
    
    // Clone Profile
    document.getElementById('btn-clone-profile').addEventListener('click', () => {
        document.getElementById('edit-profile-id').value = '';
        document.getElementById('p-name').value = `${document.getElementById('p-name').value} (Copy)`;
        document.getElementById('editor-title').textContent = 'Create New Profile';
    });
    
    // Activate Profile
    document.getElementById('btn-activate-profile').addEventListener('click', async () => {
        const id = document.getElementById('edit-profile-id').value;
        if (!id) return;
        
        const res = await apiFetch('/api/profiles/active', {
            method: 'POST',
            body: JSON.stringify({ profile_id: id })
        });
        
        if (res.error) {
            alert(`Error activating profile: ${res.error}`);
        } else {
            await pollStatus();
            await loadProfilesList();
            editProfile(id);
        }
    });
    
    // Initial Load
    await loadProfilesList();
}

// PKI CA Operations
function initPKI() {
    // Generate CA Keys
    document.getElementById('btn-generate-ca').addEventListener('click', async () => {
        const dir = document.getElementById('ca-dir').value.trim();
        const box = document.getElementById('ca-result');
        
        box.style.display = 'block';
        box.innerHTML = '<i>Generating cryptographic authority keys, please wait...</i>';
        
        const res = await apiFetch('/api/pki/generate-ca', {
            method: 'POST',
            body: JSON.stringify({ output_dir: dir })
        });
        
        if (res.error) {
            box.innerHTML = `<span style="color: var(--accent-red)">❌ Error: ${escapeHTML(res.error)}</span>`;
        } else {
            box.innerHTML = `
                <span style="color: var(--accent-green)">✅ Success! CA Key Pair generated.</span>
                <p style="margin-top: 8px; font-size: 13px;">
                    Public Key: <code>${escapeHTML(res.ca_pub_path)}</code><br>
                    Private Key: <code>${escapeHTML(res.ca_key_path)}</code>
                </p>
                <small style="color: var(--text-muted); display: block; margin-top: 4px;">Keep ca.key secure. Distribute ca.pub to nodes to enforce signature validation.</small>
            `;
        }
    });
    
    // Sign Peer ID
    const signForm = document.getElementById('pki-sign-form');
    const signResult = document.getElementById('sign-result');
    const sigContent = document.getElementById('sig-pem-content');
    
    signForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        signResult.style.display = 'none';
        
        const payload = {
            ca_priv_path: document.getElementById('sign-ca-priv').value.trim(),
            peer_id: document.getElementById('sign-peer-id').value.trim()
        };
        
        const res = await apiFetch('/api/pki/sign', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        
        if (res.error) {
            alert(`Error signing Peer ID: ${res.error}`);
        } else {
            sigContent.textContent = res.signature;
            signResult.style.display = 'block';
        }
    });
    
    // Copy signature helper
    document.getElementById('btn-copy-sig').addEventListener('click', () => {
        navigator.clipboard.writeText(sigContent.textContent);
        const btn = document.getElementById('btn-copy-sig');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy Signature PEM', 1500);
    });
}

// Logs Server-Sent Events SSE integration
function initLogs() {
    const logOutput = document.getElementById('log-output');
    const clearBtn = document.getElementById('btn-clear-logs');
    const autoscrollChk = document.getElementById('autoscroll-logs');
    
    clearBtn.addEventListener('click', () => {
        logOutput.textContent = '';
    });
    
    // Start SSE Event Source for Logs
    logEventSource = new EventSource('/api/logs');
    
    logEventSource.onmessage = (event) => {
        // Append raw log message
        const line = document.createElement('div');
        
        // Colorize lines depending on content
        let color = '#cbd5e1'; // default
        const text = event.data;
        
        if (text.includes('❌') || text.includes('FATAL') || text.includes('failed')) {
            color = '#f87171'; // red
        } else if (text.includes('⚠️') || text.includes('WARNING')) {
            color = '#fbbf24'; // yellow
        } else if (text.includes('✅') || text.includes('success')) {
            color = '#34d399'; // green
        } else if (text.includes('🤝') || text.includes('Stream') || text.includes('Reader')) {
            color = '#60a5fa'; // blue
        } else if (text.includes('🔒') || text.includes('🛡️')) {
            color = '#a78bfa'; // purple
        }
        
        line.style.color = color;
        line.textContent = text;
        
        logOutput.appendChild(line);
        
        // Auto scroll if checked
        if (autoscrollChk.checked) {
            const container = logOutput.parentNode;
            container.scrollTop = container.scrollHeight;
        }
    };
    
    logEventSource.onerror = (err) => {
        console.error('SSE Logs connection error:', err);
    };
}

// UI Utilities
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}
