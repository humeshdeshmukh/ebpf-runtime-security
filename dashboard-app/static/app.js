// SRE Observability and eBPF Security Portal JS

const statusEls = {
  minikube: document.getElementById('status-minikube'),
  k8s: document.getElementById('status-k8s'),
  tetragon: document.getElementById('status-tetragon'),
  hubble: document.getElementById('status-hubble'),
  modeBadge: document.getElementById('mode-badge')
};

const metricEls = {
  blocked: document.getElementById('metric-blocked'),
  flows: document.getElementById('metric-flows'),
};

const auditConsole = document.getElementById('security-audit-console');
const flowsBody = document.getElementById('network-flows-body');

// Chart JS setup
let eventChart = null;
const eventTimeData = [];
const eventCountData = [];

// Canvas setup for Network Map
const canvas = document.getElementById('topology-map');
const ctx = canvas.getContext('2d');

let nodes = [];
let links = [];
let particles = [];
let draggedNode = null;
let mousePos = { x: 0, y: 0 };

// Resize canvas properly
function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height || 350;
}

window.addEventListener('resize', resizeCanvas);

// Default coordinates mapped to canvas size
const nodePositions = {
  'payment-gateway': { x: 0.5, y: 0.45 },
  'compromised-pod': { x: 0.25, y: 0.65 },
  'kube-dns': { x: 0.5, y: 0.15 },
  'api.stripe.com': { x: 0.8, y: 0.35 },
  'google.com': { x: 0.8, y: 0.65 },
  'c2-server.evil.com': { x: 0.2, y: 0.35 }
};

// Initialize Chart.js
function initChart() {
  const chartCtx = document.getElementById('event-chart').getContext('2d');
  eventChart = new Chart(chartCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total Kernel Events',
          data: [],
          borderColor: '#a855f7',
          backgroundColor: 'rgba(168, 85, 247, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Blocked Actions',
          data: [],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.4,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { color: '#9ca3af' }
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { color: '#9ca3af' },
          beginAtZero: true
        }
      },
      plugins: {
        legend: { labels: { color: '#f3f4f6' } }
      }
    }
  });
}

// Fetch Status API
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const status = await res.json();
    
    // Helper to apply classes
    const updateStatusEl = (el, val) => {
      el.innerText = val;
      el.className = 'status-value ' + val.toLowerCase();
    };

    updateStatusEl(statusEls.minikube, status.minikube);
    updateStatusEl(statusEls.k8s, status.kubernetes);
    updateStatusEl(statusEls.tetragon, status.tetragon);
    updateStatusEl(statusEls.hubble, status.hubble);
  } catch (err) {
    console.error('Error fetching status:', err);
  }
}

// Fetch Telemetry API
async function fetchTelemetry() {
  try {
    const res = await fetch('/api/telemetry');
    const data = await res.json();

    // Mode Badge
    statusEls.modeBadge.innerText = data.mode.toUpperCase();
    if (data.mode.includes('Real-time')) {
      statusEls.modeBadge.className = 'badge realtime';
    } else {
      statusEls.modeBadge.className = 'badge';
    }

    // Process Tetragon Security Events
    const events = data.security_events || [];
    renderSecurityEvents(events);

    // Process Hubble Flows
    const flows = data.network_flows || [];
    renderNetworkFlows(flows);

    // Update stats cards
    const blockedCount = events.filter(e => e.status && e.status.includes('Blocked')).length;
    metricEls.blocked.innerText = blockedCount;
    metricEls.flows.innerText = flows.length;

    // Update Chart
    updateChartData(events, flows);

  } catch (err) {
    console.error('Error fetching telemetry:', err);
  }
}

// Render Security Events Terminal
function renderSecurityEvents(events) {
  if (events.length === 0) {
    auditConsole.innerHTML = '<div class="term-line loading">No security audit logs recorded yet.</div>';
    return;
  }

  auditConsole.innerHTML = '';
  events.forEach(evt => {
    const line = document.createElement('div');
    line.className = 'term-line';
    
    // Timestamp format
    const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A';
    
    const isBlocked = evt.status && evt.status.includes('Blocked');
    const statusClass = isBlocked ? 'status-blocked' : 'status-allowed';
    const statusText = isBlocked ? 'BLOCKED' : 'ALLOW';
    
    line.innerHTML = `
      <span class="time">[${timeStr}]</span>
      <span class="${statusClass}">${statusText}</span>
      <span class="pod-name">&lt;${evt.pod || 'host'}&gt;</span>
      <span class="event-text">${evt.details || ''}</span>
    `;
    auditConsole.appendChild(line);
  });
}

// Render Network Flows Table
function renderNetworkFlows(flows) {
  if (flows.length === 0) {
    flowsBody.innerHTML = '<tr><td colspan="6" class="table-loading">No active network flows found.</td></tr>';
    return;
  }

  flowsBody.innerHTML = '';
  flows.forEach(flow => {
    const row = document.createElement('tr');
    
    const timeStr = flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : 'N/A';
    const verdictClass = flow.verdict === 'FORWARDED' ? 'verdict-forwarded' : 'verdict-dropped';
    
    row.innerHTML = `
      <td>${timeStr}</td>
      <td><strong>${flow.source}</strong></td>
      <td>${flow.destination}</td>
      <td><code>${flow.destination_port}</code></td>
      <td><span class="protocol-badge">${flow.protocol}</span></td>
      <td><span class="${verdictClass}">${flow.verdict}</span></td>
    `;
    flowsBody.appendChild(row);
  });
}

// Update Chart Logic
function updateChartData(events, flows) {
  // Take last 7 data snapshots or build hourly chart
  // For demo, let's group by 10-second intervals or similar
  const labels = [];
  const totalEvents = [];
  const blockedEvents = [];

  // Parse events & group count for simple visualization
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 10 * 1000);
    labels.push(t.toLocaleTimeString());
    
    // Simulate/estimate counts based on real log entries
    const evtsInWindow = events.filter(e => {
      if (!e.timestamp) return false;
      const diff = Math.abs(new Date(e.timestamp).getTime() - t.getTime());
      return diff < 10000;
    }).length;

    const blockedInWindow = events.filter(e => {
      if (!e.timestamp) return false;
      const diff = Math.abs(new Date(e.timestamp).getTime() - t.getTime());
      return diff < 10000 && e.status && e.status.includes('Blocked');
    }).length;

    totalEvents.push(evtsInWindow + (flows.length / 10)); // approximate network events as well
    blockedEvents.push(blockedInWindow);
  }

  if (eventChart) {
    eventChart.data.labels = labels;
    eventChart.data.datasets[0].data = totalEvents;
    eventChart.data.datasets[1].data = blockedEvents;
    eventChart.update('none'); // silent update
  }
}

// Fetch Topology Config & Set coordinates
async function fetchTopology() {
  try {
    const res = await fetch('/api/topology');
    const data = await res.json();
    
    nodes = data.nodes || [];
    links = data.links || [];

    // Assign positions based on default mappings scaled to canvas size
    nodes.forEach(n => {
      const pos = nodePositions[n.id] || { x: Math.random(), y: Math.random() };
      n.x = pos.x * canvas.width;
      n.y = pos.y * canvas.height;
      n.radius = 22;
    });

    // Reset particles
    particles = [];
    links.forEach((l, idx) => {
      // Create 2 particles per link traveling at different times
      particles.push({ linkIdx: idx, progress: Math.random(), speed: 0.005 + Math.random() * 0.005 });
      particles.push({ linkIdx: idx, progress: Math.random(), speed: 0.005 + Math.random() * 0.005 });
    });

  } catch (err) {
    console.error('Error fetching topology:', err);
  }
}

// Animation Loop for Topology Map
function animate() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // 1. Draw Links
  links.forEach(l => {
    const sourceNode = nodes.find(n => n.id === l.source);
    const targetNode = nodes.find(n => n.id === l.target);

    if (sourceNode && targetNode) {
      ctx.beginPath();
      ctx.moveTo(sourceNode.x, sourceNode.y);
      ctx.lineTo(targetNode.x, targetNode.y);
      
      if (l.verdict === 'DROPPED') {
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
        ctx.lineWidth = 2.5;
        ctx.setLineDash([5, 5]);
      } else {
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.3)';
        ctx.lineWidth = 2;
        ctx.setLineDash([]);
      }
      ctx.stroke();
    }
  });
  ctx.setLineDash([]); // Reset line dash

  // 2. Draw & Animate Traffic Particles
  particles.forEach(p => {
    const l = links[p.linkIdx];
    const sourceNode = nodes.find(n => n.id === l.source);
    const targetNode = nodes.find(n => n.id === l.target);

    if (sourceNode && targetNode) {
      p.progress += p.speed;
      if (p.progress > 1.0) {
        p.progress = 0;
      }

      // If verdict is dropped, particle should explode or stop halfway
      let posX, posY;
      if (l.verdict === 'DROPPED') {
        if (p.progress > 0.5) {
          // Draw a small red ripple effect halfway
          const ripX = sourceNode.x + (targetNode.x - sourceNode.x) * 0.5;
          const ripY = sourceNode.y + (targetNode.y - sourceNode.y) * 0.5;
          ctx.beginPath();
          ctx.arc(ripX, ripY, 8 * (p.progress - 0.5) * 2, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(239, 68, 68, ${1 - (p.progress - 0.5) * 2})`;
          ctx.stroke();
          
          // Reset particle immediately
          if (p.progress > 0.9) p.progress = 0;
          return;
        }
        posX = sourceNode.x + (targetNode.x - sourceNode.x) * p.progress;
        posY = sourceNode.y + (targetNode.y - sourceNode.y) * p.progress;
        
        ctx.beginPath();
        ctx.arc(posX, posY, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#ef4444';
        ctx.shadowBlur = 10;
        ctx.shadowColor = '#ef4444';
        ctx.fill();
        ctx.shadowBlur = 0;
      } else {
        posX = sourceNode.x + (targetNode.x - sourceNode.x) * p.progress;
        posY = sourceNode.y + (targetNode.y - sourceNode.y) * p.progress;
        
        ctx.beginPath();
        ctx.arc(posX, posY, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#06b6d4';
        ctx.shadowBlur = 10;
        ctx.shadowColor = '#06b6d4';
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  });

  // 3. Draw Nodes
  nodes.forEach(n => {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    
    // Choose styling based on node type
    if (n.id === 'compromised-pod') {
      ctx.fillStyle = 'rgba(239, 68, 68, 0.2)';
      ctx.strokeStyle = '#ef4444';
    } else if (n.type === 'pod') {
      ctx.fillStyle = 'rgba(6, 182, 212, 0.2)';
      ctx.strokeStyle = '#06b6d4';
    } else if (n.type === 'service') {
      ctx.fillStyle = 'rgba(168, 85, 247, 0.2)';
      ctx.strokeStyle = '#a855f7';
    } else {
      ctx.fillStyle = 'rgba(156, 163, 175, 0.2)';
      ctx.strokeStyle = '#9ca3af';
    }
    
    ctx.lineWidth = 3;
    ctx.fill();
    ctx.stroke();

    // Node icon / text label
    ctx.font = '11px Outfit, sans-serif';
    ctx.fillStyle = '#ffffff';
    ctx.textAlign = 'center';
    
    // Shorter label on node
    let labelShort = n.id;
    if (n.id === 'payment-gateway') labelShort = 'Pay-GW';
    if (n.id === 'compromised-pod') labelShort = 'Hacker';
    if (n.id === 'api.stripe.com') labelShort = 'Stripe';
    if (n.id === 'c2-server.evil.com') labelShort = 'C2 EVIL';
    if (n.id === 'kube-dns') labelShort = 'DNS';

    ctx.fillText(labelShort, n.x, n.y + 4);
    
    // Full tooltip label below node
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.fillStyle = '#9ca3af';
    ctx.fillText(n.namespace !== 'none' ? `${n.namespace}/${n.id}` : n.id, n.x, n.y + n.radius + 14);
  });

  requestAnimationFrame(animate);
}

// Dragging Logic
canvas.addEventListener('mousedown', e => {
  const rect = canvas.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const y = e.clientY - rect.top;

  draggedNode = nodes.find(n => {
    const dist = Math.hypot(n.x - x, n.y - y);
    return dist < n.radius;
  });
});

canvas.addEventListener('mousemove', e => {
  if (draggedNode) {
    const rect = canvas.getBoundingClientRect();
    draggedNode.x = e.clientX - rect.left;
    draggedNode.y = e.clientY - rect.top;
  }
});

window.addEventListener('mouseup', () => {
  draggedNode = null;
});

// App Startup
async function init() {
  resizeCanvas();
  initChart();
  
  await fetchStatus();
  await fetchTopology();
  await fetchTelemetry();
  
  // Start canvas loop
  animate();

  // Intervals
  setInterval(fetchStatus, 5000);
  setInterval(fetchTelemetry, 3000);
}

document.addEventListener('DOMContentLoaded', init);
