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
      <!-- Search bar -->
      <div class="graph-search-wrap">
        <SearchIcon :size="16" class="graph-search-icon" />
        <input
          v-model="searchQuery"
          type="text"
          class="graph-search-input"
          placeholder="Search subject, sender, domain, IP, UPI, wallet, or hash..."
        />
        <span v-if="searchQuery" class="graph-search-count">
          {{ searchMatchIds.length }} {{ searchMatchIds.length === 1 ? 'match' : 'matches' }}
        </span>
        <button v-if="searchQuery" class="graph-search-clear" title="Clear search" @click="searchQuery = ''">
          <X :size="14" />
        </button>
      </div>

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
            <button
              v-if="selectedEmailCluster"
              class="btn-secondary view-full-btn"
              @click="openClusterReport(selectedEmailCluster)"
              :title="`Open the campaign report for ${selectedEmailCluster.cluster_id}`"
            >
              <FileText :size="14" />
              Open campaign report ({{ selectedEmailCluster.cluster_id }})
            </button>
          </div>

          <div v-else class="inspector-body">
            <div class="inspector-type indicator">
              <Tag :size="14" />
              <span>{{ prettyType(selectedNode.type) }}</span>
            </div>
            <div class="inspector-title-row">
              <div class="inspector-title mono" :title="selectedNode.label">
                {{ selectedNode.label }}
              </div>
              <button
                class="copy-btn"
                :title="`Copy ${selectedNode.label} to clipboard`"
                @click="copyToClipboard(selectedNode.label, 'ind-label')"
              >
                <Check v-if="copiedKey === 'ind-label'" :size="14" />
                <Copy v-else :size="14" />
              </button>
            </div>
            <div class="inspector-fields">
              <div class="field-row">
                <span class="field-label">Node ID</span>
                <span class="field-value mono value-with-copy">
                  <span class="value-text">{{ selectedNode.id }}</span>
                  <button
                    class="copy-btn copy-btn-inline"
                    :title="`Copy ${selectedNode.id} to clipboard`"
                    @click="copyToClipboard(selectedNode.id, 'ind-id')"
                  >
                    <Check v-if="copiedKey === 'ind-id'" :size="12" />
                    <Copy v-else :size="12" />
                  </button>
                </span>
              </div>
              <div class="field-row">
                <span class="field-label">Referenced by</span>
                <span class="field-value">
                  {{ connectedEmails.length }} {{ connectedEmails.length === 1 ? 'email' : 'emails' }}
                </span>
              </div>
            </div>

            <div v-if="connectedEmails.length > 0" class="connected-emails">
              <div class="connected-header">Connected Emails</div>
              <ul class="connected-list">
                <li
                  v-for="em in visibleConnectedEmails"
                  :key="em.id"
                  class="connected-item"
                  :class="{ 'connected-item-loading': loadingItem === em.id }"
                  @click="openReport({ id: em.id })"
                >
                  <span :class="['badge', getVerdictBadgeClass(em.verdict)]">
                    {{ em.verdict || 'Unknown' }}
                  </span>
                  <span class="connected-subject" :title="em.subject">
                    {{ em.subject || '(No Subject)' }}
                  </span>
                  <ExternalLink :size="12" class="connected-open-icon" />
                </li>
              </ul>
              <div v-if="hiddenConnectedCount > 0" class="connected-more">
                +{{ hiddenConnectedCount }} more
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Cluster summary cards -->
      <div class="clusters-section">
        <div class="clusters-header">
          <h2>Detected Clusters</h2>
          <div class="clusters-header-right">
            <button
              v-if="activeClusterId"
              class="show-all-btn"
              @click="clearActiveCluster"
            >
              Show All
            </button>
            <span class="clusters-count">{{ clusters.length }} {{ clusters.length === 1 ? 'cluster' : 'clusters' }}</span>
          </div>
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
            :class="['cluster-card', activeClusterId === c.cluster_id ? 'cluster-card-active' : '']"
            @click="toggleCluster(c)"
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
            <button
              class="cluster-report-btn"
              @click.stop="openClusterReport(c)"
            >
              <FileText :size="12" />
              View Full Report
            </button>
          </div>
        </div>
      </div>

      <!-- Clusters chat assistant -->
      <div class="chat-section">
        <ChatPanel :context="chatContext" :context-builder="buildChatContext" />
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
  Share2, Network, Inbox, Search, Mail, Tag,
  ExternalLink, Gauge, Maximize2, X, FileText, Copy, Check,
  Search as SearchIcon,
} from 'lucide-vue-next'
import { getGraphOverview, getHistoryItem } from '../api/client'
import { useAnalysisStore } from '../stores/analysis'
import { useNetworkGraph } from '../composables/useNetworkGraph'
import ChatPanel from '../components/ChatPanel.vue'

const router = useRouter()
const store = useAnalysisStore()

const nodes = ref([])
const edges = ref([])
const clusters = ref([])
const loading = ref(true)
const selectedNode = ref(null)
const loadingItem = ref(null)
const networkContainer = ref(null)
const activeClusterId = ref(null)
const searchQuery = ref('')
const copiedKey = ref(null)
let copyResetTimer = null

async function copyToClipboard(text, key) {
  if (!text) return
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(String(text))
    } else {
      // Fallback for older browsers / non-secure contexts
      const ta = document.createElement('textarea')
      ta.value = String(text)
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    copiedKey.value = key
    if (copyResetTimer) clearTimeout(copyResetTimer)
    copyResetTimer = setTimeout(() => { copiedKey.value = null }, 1200)
  } catch (err) {
    console.warn('Copy failed', err)
  }
}

function matchNodesByText(text) {
  const q = (text || '').trim().toLowerCase()
  if (!q) return []
  const hits = []
  for (const n of nodes.value) {
    const label = (n.label || '').toLowerCase()
    const id = (n.id || '').toLowerCase()
    const subject = (n.subject || '').toLowerCase()
    const sender = (n.sender || '').toLowerCase()
    if (label.includes(q) || id.includes(q) || subject.includes(q) || sender.includes(q)) {
      hits.push(n)
    }
  }
  return hits
}

const searchMatchIds = computed(() => matchNodesByText(searchQuery.value).map(n => n.id))

watch(searchQuery, (q) => {
  const trimmed = (q || '').trim()
  if (!trimmed) {
    // Empty search restores full view, overriding any prior cluster selection.
    activeClusterId.value = null
    graphCtl.clearHighlight()
    return
  }
  // Search takes precedence over any active cluster selection.
  activeClusterId.value = null
  const ids = searchMatchIds.value
  if (ids.length === 0) {
    // No matches — dim everything by highlighting an empty-but-truthy set.
    // Passing a Set with a sentinel that matches nothing yields all-dim.
    graphCtl.setHighlight(new Set(['__no_matches_sentinel__']))
    return
  }
  graphCtl.setHighlight(new Set(ids))
  if (ids.length === 1) {
    graphCtl.focusNode(ids[0])
  }
})

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

const MAX_MATCHED_NODES = 6
const MAX_NEIGHBORS_PER_NODE = 8

function neighborsOf(nodeId) {
  const out = []
  for (const e of edges.value) {
    if (e.source === nodeId) out.push({ id: e.target, edgeType: e.type })
    else if (e.target === nodeId) out.push({ id: e.source, edgeType: e.type })
  }
  return out
}

function buildRelevantNode(node) {
  const neighborIds = neighborsOf(node.id)
  if (node.type === 'email') {
    const indicators = []
    for (const { id } of neighborIds) {
      const other = nodes.value.find(n => n.id === id)
      if (!other || other.type === 'email') continue
      indicators.push({ type: other.type, value: other.label || other.id })
      if (indicators.length >= MAX_NEIGHBORS_PER_NODE) break
    }
    return {
      node_kind: 'email',
      id: node.id,
      subject: node.subject || node.label || '(No Subject)',
      sender: node.sender || null,
      verdict: node.verdict || null,
      risk_score: node.risk_score ?? null,
      connected_indicators: indicators,
    }
  }
  const emails = []
  for (const { id } of neighborIds) {
    const other = nodes.value.find(n => n.id === id)
    if (!other || other.type !== 'email') continue
    emails.push({
      subject: other.subject || other.label || '(No Subject)',
      verdict: other.verdict || null,
    })
    if (emails.length >= MAX_NEIGHBORS_PER_NODE) break
  }
  return {
    node_kind: 'indicator',
    type: node.type,
    value: node.label || node.id,
    connected_emails: emails,
    connected_email_count: neighborIds.filter(({ id }) => {
      const o = nodes.value.find(n => n.id === id)
      return o && o.type === 'email'
    }).length,
  }
}

function buildChatContext(message) {
  const base = chatContext.value ? { ...chatContext.value } : null
  if (!base) return null
  const matches = matchNodesByText(message).slice(0, MAX_MATCHED_NODES)
  if (matches.length === 0) return base
  base.relevant_nodes = matches.map(buildRelevantNode)
  return base
}

const chatContext = computed(() => {
  if (!clusters.value.length && !nodes.value.length) return null
  return {
    total_emails: nodes.value.filter(n => n.type === 'email').length,
    total_clusters: clusters.value.length,
    top_clusters: clusters.value.slice(0, 5).map(c => ({
      cluster_id: c.cluster_id,
      representative_subject: c.representative_subject,
      email_count: c.email_count,
      highest_risk_score: c.highest_risk_score,
    })),
  }
})

const emailNodeCount = computed(() => nodes.value.filter(n => n.type === 'email').length)
const indicatorNodeCount = computed(() => nodes.value.length - emailNodeCount.value)

const CONNECTED_EMAILS_VISIBLE = 10

const connectedEmails = computed(() => {
  const sel = selectedNode.value
  if (!sel || sel.type === 'email') return []
  const out = []
  for (const e of edges.value) {
    if (e.source !== sel.id && e.target !== sel.id) continue
    const otherId = e.source === sel.id ? e.target : e.source
    const other = nodes.value.find(n => n.id === otherId)
    if (!other || other.type !== 'email') continue
    if (out.some(x => x.id === other.id)) continue
    out.push({
      id: other.id,
      subject: other.subject || other.label || '(No Subject)',
      verdict: other.verdict,
      risk_score: other.risk_score,
    })
  }
  // Highest risk first, then subject alphabetical
  out.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0) || String(a.subject).localeCompare(String(b.subject)))
  return out
})

const visibleConnectedEmails = computed(() => connectedEmails.value.slice(0, CONNECTED_EMAILS_VISIBLE))
const hiddenConnectedCount = computed(() => Math.max(0, connectedEmails.value.length - CONNECTED_EMAILS_VISIBLE))

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

const selectedEmailCluster = computed(() => {
  const sel = selectedNode.value
  if (!sel || sel.type !== 'email') return null
  return clusters.value.find(c => (c.member_email_ids || []).includes(sel.id)) || null
})

function openClusterReport(cluster) {
  if (!cluster || !cluster.member_email_ids || cluster.member_email_ids.length === 0) return
  router.push({
    path: '/reports',
    query: { ids: cluster.member_email_ids.join(',') },
  })
}

function clusterNodeIdSet(cluster) {
  const emailIds = new Set(cluster.member_email_ids || [])
  const set = new Set(emailIds)
  for (const e of edges.value) {
    if (emailIds.has(e.source)) set.add(e.target)
    else if (emailIds.has(e.target)) set.add(e.source)
  }
  return set
}

function toggleCluster(cluster) {
  // Cluster interaction takes precedence over any active search.
  searchQuery.value = ''
  if (activeClusterId.value === cluster.cluster_id) {
    clearActiveCluster()
    return
  }
  activeClusterId.value = cluster.cluster_id
  graphCtl.setHighlight(clusterNodeIdSet(cluster))
}

function clearActiveCluster() {
  activeClusterId.value = null
  graphCtl.clearHighlight()
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

/* Search bar */
.graph-search-wrap {
  position: relative;
  display: flex;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 10px;
  padding: 0 12px 0 36px;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.graph-search-wrap:focus-within {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-light);
}

.graph-search-icon {
  position: absolute;
  left: 12px;
  color: var(--text-muted);
}

.graph-search-input {
  flex: 1;
  border: none;
  outline: none;
  padding: 12px 0;
  font-size: 0.92rem;
  background: transparent;
  color: var(--text-main);
}

.graph-search-count {
  font-size: 0.78rem;
  color: var(--text-muted);
  padding: 0 8px;
  white-space: nowrap;
}

.graph-search-clear {
  background: transparent;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  padding: 4px;
  border-radius: 6px;
  display: inline-flex;
  align-items: center;
}

.graph-search-clear:hover {
  background: var(--bg-page);
  color: var(--text-main);
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

.inspector-title-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
}

.value-with-copy {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
}

.value-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 220px;
}

.copy-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--border-light);
  background: var(--bg-card);
  color: var(--text-muted);
  border-radius: 6px;
  width: 28px;
  height: 28px;
  cursor: pointer;
  flex-shrink: 0;
  transition: background-color 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}

.copy-btn:hover {
  background: var(--accent-light);
  color: var(--accent);
  border-color: var(--accent);
}

.copy-btn-inline {
  width: 22px;
  height: 22px;
  border: none;
  background: transparent;
}

.copy-btn-inline:hover {
  background: var(--accent-light);
  color: var(--accent);
}

.connected-emails {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.connected-header {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}

.connected-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.connected-item {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.85rem;
  color: var(--text-main);
  transition: background-color 0.12s ease;
}

.connected-item:hover {
  background: var(--bg-page);
}

.connected-item-loading {
  opacity: 0.6;
  cursor: progress;
}

.connected-subject {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connected-open-icon {
  color: var(--text-muted);
}

.connected-more {
  font-size: 0.78rem;
  color: var(--text-muted);
  padding: 4px 8px;
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
  transition: box-shadow 0.18s ease, border-color 0.15s ease, transform 0.18s ease;
}

.cluster-card {
  cursor: pointer;
}

.cluster-card:hover {
  border-color: var(--accent-light);
  box-shadow: 0 6px 14px rgba(15, 23, 42, 0.08), 0 2px 4px rgba(29, 78, 216, 0.06);
  transform: translateY(-2px);
}

.cluster-card-active {
  border-color: var(--accent) !important;
  background: var(--accent-light);
  box-shadow: 0 2px 8px rgba(29, 78, 216, 0.15);
}

.clusters-header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.show-all-btn {
  background: var(--bg-card);
  border: 1px solid var(--accent);
  color: var(--accent);
  border-radius: 8px;
  padding: 5px 12px;
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}

.show-all-btn:hover {
  background: var(--accent-light);
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

.cluster-report-btn {
  align-self: flex-start;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  margin-top: 4px;
  padding: 5px 10px;
  border-radius: 6px;
  border: 1px solid var(--accent);
  background: var(--bg-card);
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 600;
  cursor: pointer;
  transition: background-color 0.15s ease;
}

.cluster-report-btn:hover {
  background: var(--accent-light);
}

.cluster-card-active .cluster-report-btn {
  background: var(--bg-card);
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

.chat-section {
  margin-top: 4px;
}
</style>
