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
          <span>{{ relationshipSummary?.text }}</span>
        </div>
        <div v-for="(rel, idx) in relatedEmails" :key="idx" class="related-email-row">
          <span :class="['badge', getRelBadgeClass(rel.verdict)]">{{ rel.verdict }}</span>
          <span class="related-subject" :title="rel.subject">{{ rel.subject || '(No subject)' }}</span>
          <span :class="['strength-badge', `strength-${rel.correlation_strength || 'weak'}`]">
            {{ rel.correlation_strength || 'weak' }}
          </span>
          <span v-if="rel.shared_indicators && rel.shared_indicators.length" class="indicator-pills">
            <span v-for="(ind, j) in rel.shared_indicators" :key="j" class="indicator-pill" :title="ind.value">
              {{ indicatorLabel(ind.type) }}
            </span>
          </span>
          <span v-else-if="rel.shared_via" class="indicator-pills">
            <span class="indicator-pill" :title="rel.shared_value">
              {{ indicatorLabel(rel.shared_via) }}
            </span>
          </span>
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
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { Network, Share2, Info, Maximize2, List } from 'lucide-vue-next'
import { getGraph } from '../api/client'
import { useNetworkGraph } from '../composables/useNetworkGraph'

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

const graphCtl = useNetworkGraph({ height: '380px', resize: true })

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

const indicatorTypeLabels = {
  ip: 'IP',
  domain: 'Domain',
  upi: 'UPI',
  wallet: 'Wallet',
  attachment_hash: 'File Hash',
  template_hash: 'Template',
}

const indicatorDescriptions = {
  ip: 'the same IP address',
  domain: 'the same domain',
  upi: 'the same UPI ID',
  wallet: 'the same crypto wallet',
  attachment_hash: 'an identical attachment',
  template_hash: 'an identical email template',
}

function indicatorLabel(type) {
  return indicatorTypeLabels[type] || type
}

function formatIndicatorTypes(types) {
  const descriptions = types.map(t => indicatorDescriptions[t] || `shared ${t}`)
  if (descriptions.length === 0) return 'shared infrastructure'
  if (descriptions.length === 1) return descriptions[0]
  if (descriptions.length === 2) return `${descriptions[0]} and ${descriptions[1]}`
  return `${descriptions.slice(0, -1).join(', ')}, and ${descriptions[descriptions.length - 1]}`
}

const relationshipSummary = computed(() => {
  const emails = relatedEmails.value
  if (!emails || emails.length === 0) return null

  // Determine aggregate strength
  const strengths = emails.map(e => e.correlation_strength || 'weak')
  let overallStrength = 'weak'
  if (strengths.includes('strong')) {
    overallStrength = 'strong'
  } else if (strengths.includes('moderate')) {
    overallStrength = 'moderate'
  }

  const strengthPhrases = {
    strong: 'strongly connected',
    moderate: 'connected',
    weak: 'weakly connected',
  }
  const phrase = strengthPhrases[overallStrength] || 'connected'

  // Collect distinct indicator types across all related emails
  const typeSet = new Set()
  for (const rel of emails) {
    if (rel.shared_indicators && rel.shared_indicators.length) {
      for (const ind of rel.shared_indicators) {
        if (ind.type) typeSet.add(ind.type)
      }
    } else if (rel.shared_via) {
      typeSet.add(rel.shared_via)
    }
  }

  const count = emails.length
  const reportWord = count === 1 ? 'other analyzed report' : 'other analyzed reports'
  const sharedText = formatIndicatorTypes(Array.from(typeSet))

  return {
    overallStrength,
    text: `This email is ${phrase} to ${count} ${reportWord} — they share ${sharedText}.`,
  }
})

async function toggleGraphView(visible) {
  showGraph.value = visible
  if (visible) {
    await nextTick()
    setTimeout(() => {
      graphCtl.setSize()
      graphCtl.fit()
      if (!hasNodes.value) {
        loadAndRenderGraph()
      }
    }, 60)
  }
}

function fitGraph() {
  graphCtl.fit()
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

    hasNodes.value = nodesRaw.length > 0

    // Set loading to false FIRST so Vue unblocks layout before canvas measurement
    loading.value = false
    await nextTick()

    if (!networkContainer.value || nodesRaw.length === 0) return

    graphCtl.render(networkContainer.value, data, {
      height: '380px',
      highlightId: props.emailHash || null,
    })
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

/* Phase 17 — Multi-indicator pills */
.indicator-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  flex-shrink: 0;
}

.indicator-pill {
  display: inline-block;
  background-color: var(--accent-light, #EFF6FF);
  color: var(--accent, #1D4ED8);
  border: 1px solid var(--accent, #1D4ED8);
  border-radius: 9999px;
  padding: 1px 8px;
  font-size: 0.72rem;
  font-weight: 600;
  white-space: nowrap;
  letter-spacing: 0.02em;
}

.strength-badge {
  display: inline-block;
  border-radius: 9999px;
  padding: 1px 8px;
  font-size: 0.72rem;
  font-weight: 600;
  white-space: nowrap;
  text-transform: capitalize;
  flex-shrink: 0;
}

.strength-weak {
  background-color: #F3F4F6;
  color: #6B7280;
  border: 1px solid #D1D5DB;
}

.strength-moderate {
  background-color: #FFFBEB;
  color: #B45309;
  border: 1px solid #F59E0B;
}

.strength-strong {
  background-color: #FEF2F2;
  color: #B91C1C;
  border: 1px solid #EF4444;
}
</style>
