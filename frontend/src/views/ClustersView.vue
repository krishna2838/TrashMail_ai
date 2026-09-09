<template>
  <div class="clusters-container">
    <div class="page-header">
      <div class="title-row">
        <Share2 :size="26" class="header-icon" />
        <h1>Clusters</h1>
      </div>
      <p class="subtitle">
        Cross-database campaign graph — connected components across every analyzed email.
      </p>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="card loading-card">
      <div class="spinner spinner-dark"></div>
      <span>Building infrastructure graph across all investigations...</span>
    </div>

    <!-- Empty -->
    <div v-else-if="nodes.length === 0" class="card empty-card">
      <Inbox :size="48" class="empty-icon" />
      <h2>No graph data yet</h2>
      <p class="empty-desc">
        Analyze a few emails first — this page shows shared infrastructure across everything in your database.
      </p>
      <button class="btn-primary start-btn" @click="router.push('/')">
        Analyze an Email Now
      </button>
    </div>

    <template v-else>
      <!-- Graph + inspector -->
      <div class="graph-inspector-row">
        <div class="card graph-card">
          <div class="card-header">
            <div class="title-with-icon">
              <Network :size="20" class="header-icon" />
              <h2>Infrastructure Graph</h2>
              <span class="graph-meta">{{ emailNodeCount }} emails · {{ indicatorNodeCount }} indicators · {{ edges.length }} links</span>
            </div>
            <button
              v-if="nodes.length > 0"
              class="fit-btn"
              title="Fit graph to view"
              @click="graphCtl.fit()"
            >
              <Maximize2 :size="15" />
              <span>Fit View</span>
            </button>
          </div>

          <div class="graph-wrapper">
            <div ref="networkContainer" class="vis-network-container"></div>
          </div>

          <div class="graph-legend">
            <div class="legend-item"><span class="legend-dot dot-phish"></span><span class="legend-text">Phishing Email</span></div>
            <div class="legend-item"><span class="legend-dot dot-safe"></span><span class="legend-text">Safe Email</span></div>
            <div class="legend-item"><span class="legend-dot dot-domain"></span><span class="legend-text">Domain</span></div>
            <div class="legend-item"><span class="legend-dot dot-ip"></span><span class="legend-text">IP</span></div>
            <div class="legend-item"><span class="legend-dot dot-upi"></span><span class="legend-text">UPI</span></div>
            <div class="legend-item"><span class="legend-dot dot-wallet"></span><span class="legend-text">Wallet</span></div>
            <div class="legend-item"><span class="legend-dot dot-hash"></span><span class="legend-text">Attachment</span></div>
            <div class="legend-item"><span class="legend-dot dot-template"></span><span class="legend-text">Template</span></div>
          </div>
        </div>

        <!-- Node Inspector -->
        <div class="card inspector-card">
          <div class="card-header">
            <div class="title-with-icon">
              <Search :size="18" class="header-icon" />
              <h2>Node Inspector</h2>
            </div>
          </div>

          <div v-if="!selectedNode" class="inspector-empty">
            Select a node to inspect its details.
          </div>

          <div v-else-if="selectedNode.type === 'email'" class="inspector-body">
            <div class="inspector-type email">
              <Mail :size="14" />
              <span>Email</span>
            </div>
            <div class="inspector-title" :title="selectedNode.subject || selectedNode.label">
              {{ selectedNode.subject || selectedNode.label || '(No Subject)' }}
            </div>
            <div class="inspector-sender mono" :title="selectedNode.sender">
              {{ selectedNode.sender || '' }}
            </div>
            <div class="inspector-fields">
              <div class="field-row">
                <span class="field-label">Verdict</span>
                <span :class="['badge', getVerdictBadgeClass(selectedNode.verdict)]">
                  {{ selectedNode.verdict || 'Unknown' }}
                </span>
              </div>
              <div class="field-row">
                <span class="field-label">Risk Score</span>
                <span class="risk-score" :style="{ color: getVerdictColor(selectedNode.verdict) }">
                  {{ selectedNode.risk_score ?? '—' }}/100
                </span>
              </div>
              <div v-if="selectedNode.analyzed_at" class="field-row">
                <span class="field-label">Analyzed</span>
                <span class="field-value">{{ formatDate(selectedNode.analyzed_at) }}</span>
              </div>
            </div>
            <button
              class="btn-primary view-full-btn"
              :disabled="loadingItem === selectedNode.id"
              @click="openReport(selectedNode)"
            >
              <ExternalLink :size="14" />
              View full report
            </button>
          </div>

          <div v-else class="inspector-body">
            <div class="inspector-type indicator">
              <Tag :size="14" />
              <span>{{ prettyType(selectedNode.type) }}</span>
            </div>
            <div class="inspector-title mono" :title="selectedNode.label">
              {{ selectedNode.label }}
            </div>
            <div class="inspector-fields">
              <div class="field-row">
                <span class="field-label">Node ID</span>
                <span class="field-value mono">{{ selectedNode.id }}</span>
              </div>
              <div class="field-row">
                <span class="field-label">Referenced by</span>
                <span class="field-value">
                  {{ nodeDegree(selectedNode.id) }} {{ nodeDegree(selectedNode.id) === 1 ? 'email' : 'emails' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Cluster summary cards -->
      <div class="clusters-section">
        <div class="clusters-header">
          <h2>Detected Clusters</h2>
          <span class="clusters-count">{{ clusters.length }} {{ clusters.length === 1 ? 'cluster' : 'clusters' }}</span>
        </div>

        <div v-if="clusters.length === 0" class="card empty-card small">
          <p class="empty-desc">
            No clusters yet — clusters appear once 2+ analyzed emails share an indicator (IP, domain, wallet, UPI, attachment, or template).
          </p>
        </div>

        <div v-else class="clusters-grid">
          <div
            v-for="c in clusters"
            :key="c.cluster_id"
            class="cluster-card"
          >
            <div class="cluster-top">
              <span class="cluster-id">{{ c.cluster_id }}</span>
              <span :class="['tier-badge', tierClass(c.highest_risk_score)]">
                {{ tierLabel(c.highest_risk_score) }}
              </span>
            </div>
            <div class="cluster-title" :title="c.representative_subject">
              {{ c.representative_subject }}
            </div>
            <div class="cluster-meta">
              <span class="meta-item">
                <Mail :size="12" />
                {{ c.email_count }} {{ c.email_count === 1 ? 'email' : 'emails' }}
              </span>
              <span class="meta-item">
                <Gauge :size="12" />
                Max risk {{ c.highest_risk_score }}/100
              </span>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
  Share2, Network, Inbox, Search, Mail, Tag,
  ExternalLink, Gauge, Maximize2,
} from 'lucide-vue-next'
import { getGraphOverview, getHistoryItem } from '../api/client'
import { useAnalysisStore } from '../stores/analysis'
import { useNetworkGraph } from '../composables/useNetworkGraph'

const router = useRouter()
const store = useAnalysisStore()

const nodes = ref([])
const edges = ref([])
const clusters = ref([])
const loading = ref(true)
const selectedNode = ref(null)
const loadingItem = ref(null)
const networkContainer = ref(null)

const graphCtl = useNetworkGraph({
  height: '540px',
  resize: true,
  onNodeClick: (nodeId) => {
    if (!nodeId) {
      selectedNode.value = null
      return
    }
    const n = nodes.value.find(x => x.id === nodeId)
    selectedNode.value = n || null
  },
})

const emailNodeCount = computed(() => nodes.value.filter(n => n.type === 'email').length)
const indicatorNodeCount = computed(() => nodes.value.length - emailNodeCount.value)

function nodeDegree(id) {
  let count = 0
  for (const e of edges.value) {
    if (e.source === id || e.target === id) {
      // Only count emails referencing this indicator
      const otherId = e.source === id ? e.target : e.source
      const other = nodes.value.find(n => n.id === otherId)
      if (other && other.type === 'email') count += 1
    }
  }
  return count
}

function prettyType(t) {
  return {
    ip: 'IP Address',
    domain: 'Domain',
    upi: 'UPI ID',
    wallet: 'Crypto Wallet',
    attachment_hash: 'Attachment Hash',
    template_hash: 'Template Hash',
  }[t] || (t || 'Node')
}

function getVerdictBadgeClass(v) {
  if (v === 'Safe') return 'badge-safe'
  if (v === 'Suspicious') return 'badge-suspicious'
  return 'badge-phish'
}

function getVerdictColor(v) {
  if (v === 'Safe') return 'var(--verdict-safe)'
  if (v === 'Suspicious') return 'var(--verdict-suspicious)'
  return 'var(--verdict-phish)'
}

function formatDate(s) {
  if (!s) return ''
  try { return new Date(s).toLocaleString() } catch { return s }
}

function tierLabel(score) {
  const s = Number(score) || 0
  if (s >= 85) return 'Critical'
  if (s >= 70) return 'High'
  if (s >= 35) return 'Medium'
  return 'Safe'
}

function tierClass(score) {
  const s = Number(score) || 0
  if (s >= 70) return 'tier-phish'
  if (s >= 35) return 'tier-suspicious'
  return 'tier-safe'
}

async function openReport(node) {
  if (!node || !node.id) return
  loadingItem.value = node.id
  try {
    const full = await getHistoryItem(node.id)
    if (full) {
      store.setAnalysis(full)
      router.push('/results')
    }
  } catch (err) {
    console.error('Failed to load full report', err)
  } finally {
    loadingItem.value = null
  }
}

async function loadOverview() {
  loading.value = true
  try {
    const data = await getGraphOverview(100)
    nodes.value = data.nodes || []
    edges.value = data.edges || []
    clusters.value = data.clusters || []
  } catch (err) {
    console.error('Failed to load graph overview', err)
    nodes.value = []
    edges.value = []
    clusters.value = []
  } finally {
    loading.value = false
    // Render after DOM is available
    await new Promise(r => setTimeout(r, 30))
    if (networkContainer.value && nodes.value.length > 0) {
      graphCtl.render(
        networkContainer.value,
        { nodes: nodes.value, edges: edges.value },
        { height: '540px' }
      )
    }
  }
}

onMounted(loadOverview)
</script>

<style scoped>
.clusters-container {
  max-width: 1300px;
  margin: 0 auto;
  padding: 36px 20px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.page-header {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-icon {
  color: var(--accent);
}

.subtitle {
  font-size: 0.95rem;
  color: var(--text-muted);
}

.loading-card {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 40px;
  color: var(--text-muted);
}

/* Graph + inspector layout */
.graph-inspector-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 16px;
}

@media (max-width: 1000px) {
  .graph-inspector-row {
    grid-template-columns: 1fr;
  }
}

.graph-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.title-with-icon {
  display: flex;
  align-items: center;
  gap: 10px;
}

.title-with-icon h2 {
  font-size: 1.05rem;
  margin: 0;
}

.graph-meta {
  font-size: 0.78rem;
  color: var(--text-muted);
  margin-left: 6px;
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

.graph-wrapper {
  position: relative;
  background-color: var(--bg-page);
  border-radius: 8px;
  border: 1px solid var(--border-light);
  overflow: hidden;
  height: 540px;
  min-height: 540px;
  width: 100%;
}

.vis-network-container {
  height: 540px;
  min-height: 540px;
  width: 100%;
  position: relative;
  display: block;
}

.graph-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  font-size: 0.82rem;
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
  width: 11px;
  height: 11px;
  border-radius: 50%;
}

.dot-phish { background: #FEE2E2; border: 2px solid #B91C1C; }
.dot-safe { background: #DCFCE7; border: 2px solid #15803D; }
.dot-domain { background: #DBEAFE; border: 2px solid #1D4ED8; }
.dot-ip { background: #E5E7EB; border: 2px solid #4B5563; }
.dot-upi { background: #EDE9FE; border: 2px solid #7C3AED; }
.dot-wallet { background: #FEF3C7; border: 2px solid #D97706; }
.dot-hash { background: #FFE4E6; border: 2px solid #E11D48; }
.dot-template { background: #CCFBF1; border: 2px solid #0D9488; }

/* Inspector */
.inspector-card {
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-height: 540px;
}

.inspector-empty {
  color: var(--text-muted);
  font-size: 0.9rem;
  padding: 40px 8px;
  text-align: center;
  border: 1px dashed var(--border-light);
  border-radius: 8px;
}

.inspector-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.inspector-type {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}

.inspector-type.email { color: var(--accent); }

.inspector-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-main);
  overflow-wrap: anywhere;
}

.inspector-sender {
  font-size: 0.82rem;
  color: var(--text-muted);
  overflow-wrap: anywhere;
}

.inspector-fields {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  background: var(--bg-page);
  border-radius: 8px;
}

.field-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  font-size: 0.88rem;
}

.field-label {
  color: var(--text-muted);
  font-weight: 500;
}

.field-value {
  color: var(--text-main);
  overflow-wrap: anywhere;
  text-align: right;
}

.risk-score {
  font-weight: 700;
}

.view-full-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 14px;
  font-size: 0.88rem;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

/* Clusters section */
.clusters-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.clusters-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.clusters-header h2 {
  font-size: 1.1rem;
  margin: 0;
}

.clusters-count {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.clusters-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 12px;
}

.cluster-card {
  background: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 12px;
  padding: 16px 18px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: box-shadow 0.15s ease, border-color 0.15s ease;
}

.cluster-card:hover {
  border-color: var(--accent-light);
  box-shadow: 0 2px 6px rgba(29, 78, 216, 0.08);
}

.cluster-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.cluster-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.78rem;
  color: var(--text-muted);
  font-weight: 700;
  letter-spacing: 0.05em;
}

.tier-badge {
  display: inline-block;
  border-radius: 9999px;
  padding: 2px 10px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.tier-safe {
  background: var(--verdict-safe-bg, #DCFCE7);
  color: var(--verdict-safe, #15803D);
}

.tier-suspicious {
  background: var(--verdict-suspicious-bg, #FEF3C7);
  color: var(--verdict-suspicious, #B45309);
}

.tier-phish {
  background: var(--verdict-phish-bg, #FEE2E2);
  color: var(--verdict-phish, #B91C1C);
}

.cluster-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.cluster-meta {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

/* Empty state */
.empty-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 24px;
  text-align: center;
  gap: 12px;
}

.empty-card.small {
  padding: 30px 20px;
}

.empty-icon {
  color: var(--text-light);
  margin-bottom: 8px;
}

.empty-card h2 {
  font-size: 1.3rem;
}

.empty-desc {
  font-size: 0.92rem;
  color: var(--text-muted);
  max-width: 520px;
}

.start-btn {
  margin-top: 12px;
}
</style>
