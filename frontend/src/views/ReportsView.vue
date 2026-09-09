<template>
  <div class="reports-container">
    <div class="page-header no-print">
      <div class="title-row">
        <FileText :size="26" class="header-icon" />
        <h1>Reports</h1>
      </div>
      <p class="subtitle">
        Campaign-level reports aggregated across every email in a cluster.
      </p>
    </div>

    <!-- Loading clusters -->
    <div v-if="loadingClusters" class="card loading-card no-print">
      <div class="spinner spinner-dark"></div>
      <span>Loading clusters...</span>
    </div>

    <!-- Empty: no clusters at all -->
    <div v-else-if="clusters.length === 0" class="card empty-card no-print">
      <Inbox :size="48" class="empty-icon" />
      <h2>No clusters yet</h2>
      <p class="empty-desc">
        Reports appear once 2+ analyzed emails share an indicator (IP, domain, wallet, UPI, attachment, or template).
      </p>
      <div class="empty-actions">
        <button class="btn-secondary" @click="router.push('/clusters')">View Clusters</button>
        <button class="btn-primary" @click="router.push('/')">Analyze an Email</button>
      </div>
    </div>

    <div v-else class="reports-grid">
      <!-- Left column: cluster list -->
      <aside class="cluster-list-panel card no-print">
        <div class="panel-header">
          <h2>Clusters</h2>
          <span class="panel-count">{{ clusters.length }}</span>
        </div>
        <ul class="cluster-list">
          <li
            v-for="c in clusters"
            :key="c.cluster_id"
            :class="['cluster-item', selectedClusterId === c.cluster_id ? 'cluster-item-active' : '']"
            @click="selectCluster(c)"
          >
            <div class="cluster-item-top">
              <span :class="['tier-badge', tierClass(c.highest_risk_score)]">
                {{ tierLabel(c.highest_risk_score) }}
              </span>
              <span class="cluster-item-id">{{ c.cluster_id }}</span>
            </div>
            <div class="cluster-item-title" :title="c.representative_subject">
              {{ c.representative_subject }}
            </div>
            <div class="cluster-item-meta">
              {{ c.email_count }} {{ c.email_count === 1 ? 'email' : 'emails' }}
            </div>
          </li>
        </ul>
      </aside>

      <!-- Right column: the report -->
      <section class="report-panel">
        <div v-if="!selectedCluster" class="card placeholder-card no-print">
          <Search :size="36" class="placeholder-icon" />
          <p>Select a cluster from the list to generate its campaign report.</p>
        </div>

        <div v-else class="report-doc" id="report-doc">
          <!-- Header -->
          <div class="report-header card">
            <div class="report-header-top">
              <div class="report-title-block">
                <div class="report-eyebrow">Campaign Report</div>
                <h2 class="report-title" :title="report?.executive_summary">
                  {{ selectedCluster.representative_subject }}
                </h2>
                <div class="report-meta">
                  Case reference: <span class="mono">{{ selectedCluster.cluster_id }}</span>
                  · Generated {{ generatedAt }}
                </div>
              </div>
              <div class="report-actions no-print">
                <button
                  class="btn-secondary"
                  :disabled="!report || generatingAi"
                  @click="generateAiSummary"
                  title="Generate a narrative summary via the local Ollama model"
                >
                  <Sparkles :size="14" />
                  <span>{{ generatingAi ? 'Generating...' : 'Generate AI Summary' }}</span>
                </button>
                <button class="btn-primary" :disabled="!report" @click="doPrint">
                  <Printer :size="14" />
                  <span>Print / Save as PDF</span>
                </button>
              </div>
            </div>
          </div>

          <!-- Loading report -->
          <div v-if="loadingReport" class="card loading-card">
            <div class="spinner spinner-dark"></div>
            <span>Aggregating report data...</span>
          </div>

          <template v-else-if="report">
            <!-- Key-value grid -->
            <div class="report-facts card">
              <div class="fact">
                <div class="fact-label">Linked Complaints</div>
                <div class="fact-value">{{ report.linked_complaints }}</div>
              </div>
              <div class="fact">
                <div class="fact-label">Risk Classification</div>
                <div class="fact-value">
                  <span :class="['tier-badge', tierClassFromLabel(report.risk_classification)]">
                    {{ report.risk_classification }}
                  </span>
                  <span class="fact-sub">Max risk {{ report.highest_risk_score }}/100</span>
                </div>
              </div>
              <div class="fact">
                <div class="fact-label">First Observed</div>
                <div class="fact-value">{{ formatDate(report.first_observed) || '—' }}</div>
              </div>
              <div class="fact">
                <div class="fact-label">Last Observed</div>
                <div class="fact-value">{{ formatDate(report.last_observed) || '—' }}</div>
              </div>
            </div>

            <!-- Executive summary -->
            <div class="card summary-card">
              <div class="section-header">
                <h3>Executive Summary</h3>
                <span v-if="aiError" class="ai-error">{{ aiError }}</span>
              </div>
              <p class="summary-text">{{ report.executive_summary }}</p>

              <div v-if="aiSummary" class="ai-summary-block">
                <div class="ai-summary-label">
                  <Sparkles :size="12" />
                  AI-generated narrative
                </div>
                <p class="ai-summary-text">{{ aiSummary }}</p>
              </div>
            </div>

            <!-- Shared evidence -->
            <div class="card evidence-card">
              <div class="section-header">
                <h3>Shared Evidence</h3>
                <span class="evidence-count">
                  {{ report.shared_evidence.length }} shared {{ report.shared_evidence.length === 1 ? 'indicator' : 'indicators' }}
                </span>
              </div>

              <div v-if="report.shared_evidence.length === 0" class="empty-desc small">
                No indicator appears in 2 or more member emails.
              </div>

              <template v-else>
                <!-- Pills -->
                <div class="evidence-pills">
                  <span
                    v-for="ev in report.shared_evidence"
                    :key="`${ev.type}:${ev.value}`"
                    class="pill"
                    :title="`${ev.type_label}: ${ev.value} — seen in ${ev.complaint_count} complaints`"
                  >
                    <span class="pill-label">{{ ev.type_label }}</span>
                    <span class="pill-value mono">{{ ev.value }}</span>
                    <span class="pill-count">×{{ ev.complaint_count }}</span>
                  </span>
                </div>

                <!-- Detail table -->
                <div class="table-wrap">
                  <table class="evidence-table">
                    <thead>
                      <tr>
                        <th>Class</th>
                        <th>Value</th>
                        <th class="num">Complaint Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="ev in report.shared_evidence" :key="`row:${ev.type}:${ev.value}`">
                        <td>{{ ev.type_label }}</td>
                        <td class="mono">{{ ev.value }}</td>
                        <td class="num">{{ ev.complaint_count }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </template>
            </div>

            <!-- Members -->
            <div v-if="report.victim_senders.length" class="card victims-card">
              <div class="section-header">
                <h3>Reporting Senders</h3>
                <span class="evidence-count">{{ report.victim_senders.length }}</span>
              </div>
              <ul class="victims-list mono">
                <li v-for="s in report.victim_senders" :key="s">{{ s }}</li>
              </ul>
            </div>
          </template>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { FileText, Inbox, Search, Printer, Sparkles } from 'lucide-vue-next'
import { getGraphOverview, getClusterReport, chatAsk } from '../api/client'

const router = useRouter()

const clusters = ref([])
const loadingClusters = ref(true)
const selectedClusterId = ref(null)
const selectedCluster = ref(null)
const report = ref(null)
const loadingReport = ref(false)
const aiSummary = ref('')
const aiError = ref('')
const generatingAi = ref(false)

const generatedAt = computed(() => new Date().toLocaleString())

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

function tierClassFromLabel(label) {
  if (label === 'Critical' || label === 'High') return 'tier-phish'
  if (label === 'Medium') return 'tier-suspicious'
  return 'tier-safe'
}

function formatDate(s) {
  if (!s) return ''
  try { return new Date(s).toLocaleString() } catch { return s }
}

async function loadClusters() {
  loadingClusters.value = true
  try {
    const data = await getGraphOverview(100)
    clusters.value = data.clusters || []
    if (clusters.value.length > 0) {
      selectCluster(clusters.value[0])
    }
  } catch (err) {
    console.error('Failed to load clusters for reports', err)
    clusters.value = []
  } finally {
    loadingClusters.value = false
  }
}

async function selectCluster(c) {
  selectedCluster.value = c
  selectedClusterId.value = c.cluster_id
  report.value = null
  aiSummary.value = ''
  aiError.value = ''
  loadingReport.value = true
  try {
    const data = await getClusterReport(c.member_email_ids || [])
    report.value = data
  } catch (err) {
    console.error('Failed to load cluster report', err)
    report.value = null
  } finally {
    loadingReport.value = false
  }
}

async function generateAiSummary() {
  if (!report.value) return
  aiError.value = ''
  generatingAi.value = true
  try {
    const r = report.value
    const topEvidence = (r.shared_evidence || [])
      .slice(0, 8)
      .map(e => `${e.type_label}=${e.value} (in ${e.complaint_count} complaints)`)
      .join('; ')
    const prompt = `Write a concise 3-5 sentence investigative narrative summarizing this phishing/scam campaign for a report.

Cluster: ${selectedCluster.value?.cluster_id}
Representative subject: ${selectedCluster.value?.representative_subject}
Linked complaints: ${r.linked_complaints}
Risk classification: ${r.risk_classification} (max score ${r.highest_risk_score}/100)
First observed: ${r.first_observed || 'unknown'}
Last observed: ${r.last_observed || 'unknown'}
Shared evidence: ${topEvidence || 'none'}

Keep the tone factual and evidentiary — no speculation beyond what the data supports.`
    const resp = await chatAsk(prompt, null, [])
    const text = (resp && (resp.reply || resp.response || resp.message)) || ''
    if (!text) throw new Error('Empty model response')
    aiSummary.value = text.trim()
  } catch (err) {
    console.error('AI summary generation failed', err)
    aiError.value = 'AI summary unavailable — the template summary above is still valid.'
  } finally {
    generatingAi.value = false
  }
}

function doPrint() {
  window.print()
}

onMounted(loadClusters)
</script>

<style scoped>
.reports-container {
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
  padding: 32px;
  color: var(--text-muted);
}

.reports-grid {
  display: grid;
  grid-template-columns: 300px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

@media (max-width: 900px) {
  .reports-grid {
    grid-template-columns: 1fr;
  }
}

/* Left panel */
.cluster-list-panel {
  padding: 0;
  overflow: hidden;
  position: sticky;
  top: 20px;
  max-height: calc(100vh - 40px);
  display: flex;
  flex-direction: column;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  padding: 16px 18px;
  border-bottom: 1px solid var(--border-light);
}

.panel-header h2 {
  font-size: 1rem;
  margin: 0;
}

.panel-count {
  font-size: 0.82rem;
  color: var(--text-muted);
}

.cluster-list {
  list-style: none;
  padding: 8px;
  margin: 0;
  overflow-y: auto;
}

.cluster-item {
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: background-color 0.15s ease;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.cluster-item:hover {
  background: var(--bg-page);
}

.cluster-item-active {
  background: var(--accent-light) !important;
  outline: 1px solid var(--accent);
}

.cluster-item-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.cluster-item-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.75rem;
  color: var(--text-muted);
  font-weight: 700;
  letter-spacing: 0.05em;
}

.cluster-item-title {
  font-size: 0.92rem;
  font-weight: 600;
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.cluster-item-meta {
  font-size: 0.78rem;
  color: var(--text-muted);
}

/* Tier badges */
.tier-badge {
  display: inline-block;
  border-radius: 9999px;
  padding: 2px 10px;
  font-size: 0.7rem;
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

/* Right panel — the report */
.report-panel {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.report-doc {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.placeholder-card {
  padding: 60px 24px;
  text-align: center;
  color: var(--text-muted);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
}

.placeholder-icon {
  color: var(--text-light);
}

.report-header-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  flex-wrap: wrap;
}

.report-eyebrow {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--accent);
}

.report-title {
  font-size: 1.35rem;
  margin: 6px 0 6px;
  color: var(--text-main);
}

.report-meta {
  font-size: 0.82rem;
  color: var(--text-muted);
}

.report-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.report-actions button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  font-size: 0.88rem;
}

.report-facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 20px;
}

.fact {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.fact-label {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}

.fact-value {
  font-size: 1.2rem;
  font-weight: 600;
  color: var(--text-main);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.fact-sub {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-weight: 500;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.section-header h3 {
  font-size: 1rem;
  margin: 0;
}

.evidence-count {
  font-size: 0.82rem;
  color: var(--text-muted);
}

.summary-text {
  font-size: 0.95rem;
  line-height: 1.55;
  color: var(--text-main);
  margin: 0;
}

.ai-summary-block {
  margin-top: 14px;
  padding: 12px 14px;
  background: var(--accent-light);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
}

.ai-summary-label {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--accent);
  margin-bottom: 6px;
}

.ai-summary-text {
  margin: 0;
  font-size: 0.92rem;
  color: var(--text-main);
  line-height: 1.55;
}

.ai-error {
  font-size: 0.8rem;
  color: var(--verdict-phish);
}

/* Evidence pills (reuses Phase 19 style) */
.evidence-pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 9999px;
  background: #F1F3F5;
  color: var(--text-muted);
  font-size: 0.78rem;
  max-width: 280px;
  overflow: hidden;
}

.pill-label {
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-size: 0.68rem;
  color: var(--text-light, #9CA3AF);
}

.pill-value {
  color: var(--text-main);
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 160px;
}

.pill-count {
  font-weight: 700;
  color: var(--accent);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

/* Evidence table */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-light);
  border-radius: 8px;
}

.evidence-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

.evidence-table th {
  background: var(--bg-page);
  padding: 10px 14px;
  text-align: left;
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border-light);
}

.evidence-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-light);
  vertical-align: middle;
}

.evidence-table tbody tr:last-child td {
  border-bottom: none;
}

.evidence-table .num {
  text-align: right;
  font-weight: 600;
}

.victims-list {
  margin: 0;
  padding: 0 0 0 18px;
  font-size: 0.88rem;
  color: var(--text-main);
  columns: 2;
  column-gap: 24px;
}

.victims-list li {
  break-inside: avoid;
  margin-bottom: 4px;
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

.empty-desc.small {
  padding: 6px 4px;
}

.empty-actions {
  display: flex;
  gap: 10px;
  margin-top: 8px;
}

/* Print */
@media print {
  .no-print { display: none !important; }
  .reports-container { padding: 0; max-width: none; }
  .reports-grid {
    display: block;
  }
  .report-panel { gap: 12px; }
  .card {
    box-shadow: none !important;
    border: 1px solid #D1D5DB !important;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .report-title { font-size: 1.4rem; }
}
</style>
