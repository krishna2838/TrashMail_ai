<template>
  <div class="card graph-card">
    <div class="card-header">
      <div class="title-with-icon">
        <Network :size="20" class="header-icon" />
        <h2>{{ title }}</h2>
      </div>
      <div class="header-actions">
        <button 
          v-if="!loading && !error && hasNodes" 
          class="fit-btn" 
          title="Fit graph to view"
          @click="fitGraph"
        >
          <Maximize2 :size="15" />
          <span>Fit View</span>
        </button>
        <span v-if="campaignSize > 0" class="campaign-tag">
          Campaign Detected
        </span>
      </div>
    </div>

    <!-- Campaign Headline Banner -->
    <div v-if="campaignSize > 0" class="campaign-headline">
      <Share2 :size="18" class="headline-icon" />
      <span>
        <strong>Campaign Alert:</strong> Linked to {{ campaignSize }} other analyzed {{ campaignSize === 1 ? 'email' : 'emails' }} via shared infrastructure.
      </span>
    </div>

    <!-- Graph Container Wrapper -->
    <div class="graph-wrapper">
      <!-- Loading Overlay -->
      <div v-if="loading" class="graph-overlay">
        <div class="spinner spinner-dark"></div>
        <span>Constructing graph visualization from Neo4j...</span>
      </div>

      <!-- Error Overlay -->
      <div v-else-if="error" class="graph-overlay">
        <p>{{ error }}</p>
      </div>

      <!-- Empty Nodes Overlay -->
      <div v-else-if="!hasNodes" class="graph-overlay">
        <p>No graph nodes found for this analysis.</p>
      </div>

      <!-- vis-network canvas container: ALWAYS mounted with concrete pixel dimensions -->
      <div ref="networkContainer" class="vis-network-container"></div>

      <!-- Empty state banner when only current email exists -->
      <div v-if="!loading && !error && campaignSize === 0 && !hideNotice && !graphData" class="single-email-notice">
        <Info :size="16" />
        <span>No connections to other analyzed emails yet — this is the first sighting of this infrastructure.</span>
      </div>
    </div>

    <!-- Graph Legend -->
    <div class="graph-legend">
      <div class="legend-item">
        <span class="legend-dot dot-phish"></span>
        <span class="legend-text">Phishing Email</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-safe"></span>
        <span class="legend-text">Safe Email</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-domain"></span>
        <span class="legend-text">Domain</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-ip"></span>
        <span class="legend-text">IP Node</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-upi"></span>
        <span class="legend-text">UPI ID</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-wallet"></span>
        <span class="legend-text">Crypto Wallet</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-hash"></span>
        <span class="legend-text">Attachment Hash</span>
      </div>
      <div class="legend-item">
        <span class="legend-dot dot-template"></span>
        <span class="legend-text">Template Hash</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, onBeforeUnmount, nextTick } from 'vue'
import { Network, Share2, Info, Maximize2 } from 'lucide-vue-next'
import { Network as VisNetwork, DataSet } from 'vis-network/standalone'
import { getGraph } from '../api/client'

const props = defineProps({
  emailHash: {
    type: String,
    default: '',
  },
  campaign: {
    type: Object,
    default: () => ({ related_emails: [], campaign_size: 0 }),
  },
  graphData: {
    type: Object,
    default: null,
  },
  title: {
    type: String,
    default: 'Infrastructure & Campaign Graph',
  },
  hideNotice: {
    type: Boolean,
    default: false,
  },
})

const networkContainer = ref(null)
const loading = ref(true)
const error = ref(null)
const hasNodes = ref(true)
let networkInstance = null
let resizeObserver = null

const campaignSize = computed(() => {
  return props.campaign?.campaign_size || 0
})

function fitGraph() {
  if (networkInstance) {
    networkInstance.fit({
      animation: {
        duration: 400,
        easingFunction: 'easeInOutQuad',
      },
    })
  }
}

function getNodeColor(node) {
  if (node.type === 'email') {
    if (node.verdict === 'Safe') {
      return { 
        background: '#F0FDF4', 
        border: '#15803D', 
        highlight: { background: '#DCFCE7', border: '#15803D' },
        hover: { background: '#DCFCE7', border: '#15803D' }
      }
    } else if (node.verdict === 'Suspicious') {
      return { 
        background: '#FFFBEB', 
        border: '#B45309', 
        highlight: { background: '#FEF3C7', border: '#B45309' },
        hover: { background: '#FEF3C7', border: '#B45309' }
      }
    } else {
      return { 
        background: '#FEF2F2', 
        border: '#B91C1C', 
        highlight: { background: '#FEE2E2', border: '#B91C1C' },
        hover: { background: '#FEE2E2', border: '#B91C1C' }
      }
    }
  } else if (node.type === 'domain') {
    return { 
      background: '#EFF6FF', 
      border: '#1D4ED8', 
      highlight: { background: '#DBEAFE', border: '#1D4ED8' },
      hover: { background: '#DBEAFE', border: '#1D4ED8' }
    }
  } else if (node.type === 'upi') {
    return { 
      background: '#F5F3FF', 
      border: '#7C3AED', 
      highlight: { background: '#EDE9FE', border: '#7C3AED' },
      hover: { background: '#EDE9FE', border: '#7C3AED' }
    }
  } else if (node.type === 'wallet') {
    return { 
      background: '#FFFBEB', 
      border: '#D97706', 
      highlight: { background: '#FEF3C7', border: '#D97706' },
      hover: { background: '#FEF3C7', border: '#D97706' }
    }
  } else if (node.type === 'attachment_hash') {
    return { 
      background: '#FFF1F2', 
      border: '#E11D48', 
      highlight: { background: '#FFE4E6', border: '#E11D48' },
      hover: { background: '#FFE4E6', border: '#E11D48' }
    }
  } else if (node.type === 'template_hash') {
    return { 
      background: '#F0FDFA', 
      border: '#0D9488', 
      highlight: { background: '#CCFBF1', border: '#0D9488' },
      hover: { background: '#CCFBF1', border: '#0D9488' }
    }
  } else {
    // IP
    return { 
      background: '#F3F4F6', 
      border: '#4B5563', 
      highlight: { background: '#E5E7EB', border: '#374151' },
      hover: { background: '#E5E7EB', border: '#374151' }
    }
  }
}

async function loadAndRenderGraph() {
  if (!props.emailHash && !props.graphData) return
  loading.value = true
  error.value = null

  try {
    let data
    if (props.graphData) {
      data = props.graphData
    } else {
      data = await getGraph(props.emailHash, 2)
    }
    const nodesRaw = data.nodes || []
    const edgesRaw = data.edges || []

    hasNodes.value = nodesRaw.length > 0

    // Set loading to false FIRST so Vue unblocks layout before canvas measurement
    loading.value = false
    await nextTick()

    if (!networkContainer.value || nodesRaw.length === 0) return

    // Transform nodes
    const visNodes = nodesRaw.map(n => {
      const colorScheme = getNodeColor(n)
      const isCurrent = n.id === props.emailHash
      let labelText = n.label || n.id
      if (n.type === 'email' && labelText.length > 28) {
        labelText = labelText.slice(0, 25) + '...'
      }

      let nodeShape = 'box'
      if (n.type === 'domain') nodeShape = 'ellipse'
      else if (n.type === 'ip') nodeShape = 'database'
      else if (n.type === 'upi') nodeShape = 'diamond'
      else if (n.type === 'wallet') nodeShape = 'hexagon'
      else if (n.type === 'attachment_hash') nodeShape = 'box'
      else if (n.type === 'template_hash') nodeShape = 'box'

      return {
        id: n.id,
        label: labelText,
        title: `${n.type.toUpperCase()}: ${n.label || n.id}${n.verdict ? ` [${n.verdict}]` : ''}`,
        shape: nodeShape,
        margin: { top: 8, bottom: 8, left: 12, right: 12 },
        borderWidth: isCurrent ? 3 : 1.5,
        color: colorScheme,
        font: {
          face: 'Inter, system-ui, -apple-system, sans-serif',
          size: isCurrent ? 13 : 12,
          color: '#111827',
          bold: isCurrent,
        },
        shadow: {
          enabled: true,
          color: 'rgba(0,0,0,0.06)',
          size: 4,
          x: 1,
          y: 2,
        },
      }
    })

    // Transform edges
    const visEdges = edgesRaw.map((e, idx) => ({
      id: `edge-${idx}`,
      from: e.source,
      to: e.target,
      label: e.type,
      arrows: {
        to: { enabled: true, scaleFactor: 0.7 }
      },
      color: { 
        color: '#9CA3AF', 
        highlight: '#1D4ED8',
        hover: '#1D4ED8',
        opacity: 0.9,
      },
      font: { 
        size: 10, 
        color: '#6B7280', 
        face: 'Inter, system-ui, sans-serif',
        align: 'horizontal',
        background: '#FFFFFF',
        strokeWidth: 0,
      },
      smooth: { 
        type: 'cubicBezier', 
        roundness: 0.25 
      },
    }))

    const networkData = {
      nodes: new DataSet(visNodes),
      edges: new DataSet(visEdges),
    }

    const options = {
      autoResize: true,
      height: '100%',
      width: '100%',
      layout: {
        improvedLayout: true,
      },
      physics: {
        enabled: true,
        solver: 'barnesHut',
        barnesHut: {
          gravitationalConstant: -2500,
          centralGravity: 0.25,
          springLength: 130,
          springConstant: 0.04,
          damping: 0.09,
          avoidOverlap: 0.6,
        },
        stabilization: {
          enabled: true,
          iterations: 150,
          updateInterval: 25,
          fit: true,
        },
      },
      interaction: {
        hover: true,
        hoverConnectedEdges: true,
        tooltipDelay: 150,
        zoomView: true,
        dragView: true,
      },
    }

    if (networkInstance) {
      networkInstance.destroy()
      networkInstance = null
    }

    networkInstance = new VisNetwork(networkContainer.value, networkData, options)

    // Ensure proper sizing and fit once stabilization completes
    networkInstance.once('stabilizationIterationsDone', () => {
      if (networkInstance) {
        networkInstance.fit({
          animation: {
            duration: 350,
            easingFunction: 'easeInOutQuad',
          },
        })
      }
    })

    networkInstance.once('afterDrawing', () => {
      if (networkInstance) {
        networkInstance.fit()
      }
    })

    // Fallback timer to guarantee fit after DOM settles
    setTimeout(() => {
      if (networkInstance) {
        networkInstance.redraw()
        networkInstance.fit()
      }
    }, 250)

    // Set up ResizeObserver to handle container size shifts
    if (!resizeObserver && window.ResizeObserver && networkContainer.value) {
      resizeObserver = new ResizeObserver(() => {
        if (networkInstance) {
          networkInstance.redraw()
        }
      })
      resizeObserver.observe(networkContainer.value)
    }

  } catch (err) {
    console.error('Failed to load graph', err)
    error.value = 'Could not load graph visualization from server.'
    loading.value = false
  }
}

onMounted(() => {
  loadAndRenderGraph()
})

watch([() => props.emailHash, () => props.graphData], () => {
  loadAndRenderGraph()
}, { deep: true })

onBeforeUnmount(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  if (networkInstance) {
    networkInstance.destroy()
    networkInstance = null
  }
})
</script>

<style scoped>
.graph-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.title-with-icon {
  display: flex;
  align-items: center;
  gap: 10px;
}

.header-icon {
  color: var(--accent);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.fit-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 0.8rem;
  font-family: inherit;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s ease;
}

.fit-btn:hover {
  background-color: var(--accent-light);
  border-color: var(--accent);
  color: var(--accent);
}

.campaign-tag {
  background-color: var(--verdict-phish-bg);
  color: var(--verdict-phish);
  border: 1px solid var(--verdict-phish);
  font-weight: 600;
  font-size: 0.8rem;
  padding: 3px 10px;
  border-radius: 9999px;
}

.campaign-headline {
  display: flex;
  align-items: center;
  gap: 10px;
  background-color: var(--verdict-phish-bg);
  border-left: 4px solid var(--verdict-phish);
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 0.92rem;
  color: var(--text-main);
}

.headline-icon {
  color: var(--verdict-phish);
  flex-shrink: 0;
}

.graph-wrapper {
  position: relative;
  background-color: var(--bg-page);
  border-radius: 8px;
  border: 1px solid var(--border-light);
  overflow: hidden;
  height: 380px;
  min-height: 380px;
  width: 100%;
}

.vis-network-container {
  height: 380px;
  min-height: 380px;
  width: 100%;
  position: relative;
  display: block;
}

.graph-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(248, 249, 251, 0.92);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--text-muted);
  font-size: 0.95rem;
  z-index: 10;
}

.single-email-notice {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  background-color: rgba(255, 255, 255, 0.92);
  backdrop-filter: blur(4px);
  border-top: 1px solid var(--border-light);
  padding: 8px 14px;
  font-size: 0.84rem;
  color: var(--text-muted);
  z-index: 5;
}

.graph-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 0.85rem;
  color: var(--text-muted);
  padding-top: 8px;
  border-top: 1px solid var(--border-light);
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
}

.legend-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.dot-phish {
  background-color: var(--verdict-phish-bg);
  border: 2px solid var(--verdict-phish);
}

.dot-safe {
  background-color: var(--verdict-safe-bg);
  border: 2px solid var(--verdict-safe);
}

.dot-domain {
  background-color: var(--accent-light);
  border: 2px solid var(--accent);
}

.dot-ip {
  background-color: #F3F4F6;
  border: 2px solid #4B5563;
}

.dot-upi {
  background-color: #F5F3FF;
  border: 2px solid #7C3AED;
}

.dot-wallet {
  background-color: #FFFBEB;
  border: 2px solid #D97706;
}

.dot-hash {
  background-color: #FFF1F2;
  border: 2px solid #E11D48;
}

.dot-template {
  background-color: #F0FDFA;
  border: 2px solid #0D9488;
}
</style>
