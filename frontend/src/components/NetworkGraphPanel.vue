<template>
  <div class="card graph-card">
    <div class="card-header">
      <div class="title-with-icon">
        <Network :size="20" class="header-icon" />
        <h2>{{ title }}</h2>
      </div>
      <div class="header-actions">
        <button 
          v-if="showGraph && !loading && !error && hasNodes" 
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

    <!-- Part D — Summary card (default for single-email view) -->
    <div v-if="!isBatchMode" v-show="!showGraph" class="campaign-summary-view">
      <!-- Related emails list -->
      <div v-if="relatedEmails.length > 0" class="related-list">
        <div class="related-intro">
          <span>
            Linked to <strong>{{ relatedEmails.length }}</strong> other analyzed {{ relatedEmails.length === 1 ? 'report' : 'reports' }}
            <template v-if="primaryLink"> via a shared {{ primaryLink.type }}
              (<code class="shared-val">{{ primaryLink.value }}</code>)
            </template>
          </span>
        </div>
        <div v-for="(rel, idx) in relatedEmails" :key="idx" class="related-email-row">
          <span :class="['badge', getRelBadgeClass(rel.verdict)]">{{ rel.verdict }}</span>
          <span class="related-subject" :title="rel.subject">{{ rel.subject || '(No subject)' }}</span>
          <span class="related-link-type">via {{ rel.shared_via }}</span>
        </div>
      </div>

      <!-- Empty state (no campaign matches) -->
      <div v-else-if="!loading && !error" class="summary-empty">
        <Info :size="16" />
        <span>No connections to other analyzed emails yet — this is the first sighting of this infrastructure.</span>
      </div>

      <!-- Toggle to advanced view -->
      <button 
        v-if="!loading && hasNodes"
        class="toggle-graph-btn btn-secondary" 
        @click="toggleGraphView(true)"
      >
        <Network :size="15" />
        <span>Show Infrastructure Graph</span>
      </button>
    </div>

    <!-- Advanced graph view (always shown for batch mode, toggleable for single) -->
    <div :class="['graph-section', { 'graph-hidden': !isBatchMode && !showGraph }]">
      <!-- Toggle back to summary (single-email only) -->
      <button 
        v-if="!isBatchMode"
        class="toggle-graph-btn btn-secondary toggle-back"
        @click="toggleGraphView(false)"
      >
        <List :size="15" />
        <span>Show Summary View</span>
      </button>

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
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, onBeforeUnmount, nextTick } from 'vue'
import { Network, Share2, Info, Maximize2, List } from 'lucide-vue-next'
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
const showGraph = ref(false)
let networkInstance = null
let resizeObserver = null

// Part D — computed helpers for summary vs graph view
const isBatchMode = computed(() => {
  return Boolean(props.graphData)
})

const campaignSize = computed(() => {
  return props.campaign?.campaign_size || 0
})

const relatedEmails = computed(() => {
  return props.campaign?.related_emails || []
})

const primaryLink = computed(() => {
  const emails = relatedEmails.value
  if (!emails || emails.length === 0) return null
  const first = emails[0]
  if (!first.shared_via || !first.shared_value) return null
  const typeLabels = {
    ip: 'IP address',
    domain: 'domain',
    upi: 'UPI ID',
    wallet: 'crypto wallet',
    attachment_hash: 'attachment hash',
    template_hash: 'template hash',
  }
  return {
    type: typeLabels[first.shared_via] || first.shared_via,
    value: first.shared_value,
  }
})

function getRelBadgeClass(verdict) {
  if (verdict === 'Safe') return 'badge-safe'
  if (verdict === 'Suspicious') return 'badge-suspicious'
  return 'badge-phish'
}

async function toggleGraphView(visible) {
  showGraph.value = visible
  if (visible) {
    await nextTick()
    setTimeout(() => {
      if (networkInstance) {
        networkInstance.setSize('100%', '380px')
        networkInstance.redraw()
        networkInstance.fit({
          animation: {
            duration: 350,
            easingFunction: 'easeInOutQuad',
          },
        })
      } else {
        loadAndRenderGraph()
      }
    }, 60)
  }
}

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
          avoidOverlap: 0.5,
        },
        stabilization: {
          enabled: true,
          iterations: 200,
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

    // Ensure proper sizing, fit, and freeze physics once stabilization completes
    networkInstance.once('stabilizationIterationsDone', () => {
      if (networkInstance) {
        networkInstance.setOptions({ physics: false })
        networkInstance.fit({
          animation: {
            duration: 350,
            easingFunction: 'easeInOutQuad',
          },
        })
      }
    })

    networkInstance.once('stabilized', () => {
      if (networkInstance) {
        networkInstance.setOptions({ physics: false })
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
      resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          if (entry.contentRect.width > 20 && entry.contentRect.height > 20) {
            if (networkInstance) {
              networkInstance.setSize('100%', '380px')
              networkInstance.redraw()
              networkInstance.fit()
            }
          }
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

/* Part D — Summary view & toggle */
.campaign-summary-view {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.related-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.related-intro {
  font-size: 0.92rem;
  color: var(--text-main);
  line-height: 1.5;
  padding: 10px 14px;
  background-color: var(--bg-page);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
}

.shared-val {
  background-color: rgba(0, 0, 0, 0.06);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.88em;
  word-break: break-all;
}

.related-email-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  background-color: #FFFFFF;
  border: 1px solid var(--border-light);
  border-radius: 6px;
  font-size: 0.9rem;
}

.related-subject {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-main);
  font-weight: 500;
}

.related-link-type {
  font-size: 0.8rem;
  color: var(--text-muted);
  white-space: nowrap;
}

.summary-empty {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  background-color: var(--bg-page);
  border-radius: 8px;
  color: var(--text-muted);
  font-size: 0.9rem;
}

.toggle-graph-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  align-self: flex-start;
  font-size: 0.85rem;
  padding: 6px 14px;
}

.toggle-back {
  margin-bottom: 4px;
}

.graph-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.graph-hidden {
  display: none !important;
}
</style>
