<template>
  <div class="dashboard-container">
    <div class="dashboard-header">
      <div class="title-row">
        <LayoutGrid :size="26" class="header-icon" />
        <h1>Dashboard</h1>
      </div>
      <p class="subtitle">Overview of your investigation activity.</p>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="card loading-card">
      <div class="spinner spinner-dark"></div>
      <span>Loading dashboard data...</span>
    </div>

    <!-- Empty state -->
    <div v-else-if="historyList.length === 0" class="card empty-card">
      <Inbox :size="48" class="empty-icon" />
      <h2>No analyses yet</h2>
      <p class="empty-desc">
        Analyze your first email to start building a forensic audit trail. Your dashboard will populate automatically.
      </p>
      <button class="btn-primary start-btn" @click="router.push('/')">
        Analyze your first email
      </button>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Stat cards -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Analyzed</div>
          <div class="stat-value">{{ stats.total }}</div>
          <span class="stat-dot dot-total"></span>
        </div>
        <div class="stat-card">
          <div class="stat-label">Phishing/Scam</div>
          <div class="stat-value" :style="{ color: 'var(--verdict-phish)' }">{{ stats.phishing }}</div>
          <span class="stat-dot dot-phish"></span>
        </div>
        <div class="stat-card">
          <div class="stat-label">Suspicious</div>
          <div class="stat-value" :style="{ color: 'var(--verdict-suspicious)' }">{{ stats.suspicious }}</div>
          <span class="stat-dot dot-suspicious"></span>
        </div>
        <div class="stat-card">
          <div class="stat-label">Safe</div>
          <div class="stat-value" :style="{ color: 'var(--verdict-safe)' }">{{ stats.safe }}</div>
          <span class="stat-dot dot-safe"></span>
        </div>
      </div>

      <!-- Verdict distribution donut -->
      <div v-if="stats.total > 0" class="card donut-card">
        <div class="donut-header">
          <h2>Verdict Distribution</h2>
          <span class="donut-total">{{ stats.total }} total</span>
        </div>
        <div class="donut-body">
          <div
            class="donut"
            :style="{ background: donutGradient }"
            :aria-label="`Phishing ${donutPct.phishing}%, Suspicious ${donutPct.suspicious}%, Safe ${donutPct.safe}%`"
            role="img"
          >
            <div class="donut-hole">
              <div class="donut-hole-num">{{ stats.total }}</div>
              <div class="donut-hole-label">emails</div>
            </div>
          </div>
          <ul class="donut-legend">
            <li>
              <span class="legend-swatch swatch-phish"></span>
              <span class="legend-name">Phishing/Scam</span>
              <span class="legend-value">{{ stats.phishing }} <span class="legend-pct">({{ donutPct.phishing }}%)</span></span>
            </li>
            <li>
              <span class="legend-swatch swatch-suspicious"></span>
              <span class="legend-name">Suspicious</span>
              <span class="legend-value">{{ stats.suspicious }} <span class="legend-pct">({{ donutPct.suspicious }}%)</span></span>
            </li>
            <li>
              <span class="legend-swatch swatch-safe"></span>
              <span class="legend-name">Safe</span>
              <span class="legend-value">{{ stats.safe }} <span class="legend-pct">({{ donutPct.safe }}%)</span></span>
            </li>
          </ul>
        </div>
      </div>

      <!-- Recent activity -->
      <div class="card table-card">
        <div class="table-header">
          <h2>Recent Activity</h2>
          <router-link to="/history" class="view-all-link">View all →</router-link>
        </div>
        <div class="table-responsive">
          <table class="history-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Subject</th>
                <th>Sender</th>
                <th>Verdict</th>
                <th>Threat Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in recentItems" :key="item.id || item.email_hash">
                <td class="date-cell">{{ formatDate(item.analyzed_at) }}</td>
                <td class="subject-cell font-medium" :title="item.subject">{{ item.subject }}</td>
                <td class="sender-cell mono" :title="item.sender">{{ item.sender }}</td>
                <td>
                  <span :class="['badge', getVerdictBadgeClass(item.verdict)]">
                    {{ item.verdict }}
                  </span>
                </td>
                <td>
                  <span class="score-pill" :style="{ color: getVerdictColor(item.verdict) }">
                    {{ item.risk_score }}/100
                  </span>
                </td>
                <td class="actions-cell">
                  <button
                    class="btn-secondary action-btn"
                    :disabled="loadingItem === (item.id || item.email_hash)"
                    @click="viewAnalysis(item)"
                  >
                    <Eye :size="14" />
                    <span>View</span>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { LayoutGrid, Inbox, Eye } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import { getHistory, getHistoryItem } from '../api/client'

const router = useRouter()
const store = useAnalysisStore()

const historyList = ref([])
const loading = ref(true)
const loadingItem = ref(null)

const stats = computed(() => {
  const list = historyList.value
  return {
    total: list.length,
    phishing: list.filter(i => i.verdict === 'Phishing/Scam').length,
    suspicious: list.filter(i => i.verdict === 'Suspicious').length,
    safe: list.filter(i => i.verdict === 'Safe').length,
  }
})

const recentItems = computed(() => historyList.value.slice(0, 10))

const donutPct = computed(() => {
  const t = stats.value.total || 0
  if (t === 0) return { phishing: 0, suspicious: 0, safe: 0 }
  return {
    phishing: Math.round((stats.value.phishing / t) * 100),
    suspicious: Math.round((stats.value.suspicious / t) * 100),
    safe: Math.round((stats.value.safe / t) * 100),
  }
})

const donutGradient = computed(() => {
  const t = stats.value.total || 0
  if (t === 0) return '#F1F3F5'
  const phishDeg = (stats.value.phishing / t) * 360
  const suspDeg = (stats.value.suspicious / t) * 360
  const start1 = 0
  const end1 = phishDeg
  const start2 = end1
  const end2 = end1 + suspDeg
  const start3 = end2
  const end3 = 360
  return (
    `conic-gradient(` +
    `var(--verdict-phish) ${start1}deg ${end1}deg,` +
    `var(--verdict-suspicious) ${start2}deg ${end2}deg,` +
    `var(--verdict-safe) ${start3}deg ${end3}deg)`
  )
})

function formatDate(isoStr) {
  if (!isoStr) return 'Just now'
  try {
    return new Date(isoStr).toLocaleString()
  } catch {
    return isoStr
  }
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

async function loadHistory() {
  loading.value = true
  try {
    const data = await getHistory(50)
    if (data && Array.isArray(data) && data.length > 0) {
      historyList.value = data
    } else {
      historyList.value = store.history || []
    }
  } catch (err) {
    console.warn('Could not fetch history from backend, falling back to local cache', err)
    historyList.value = store.history || []
  } finally {
    loading.value = false
  }
}

async function viewAnalysis(item) {
  const hash = item.id || item.email_hash
  if (!hash) return

  if (store.currentAnalysis?.email_hash === hash) {
    router.push('/results')
    return
  }

  loadingItem.value = hash
  try {
    const fullData = await getHistoryItem(hash)
    if (fullData) {
      store.setAnalysis(fullData)
      router.push('/results')
    } else {
      router.push('/')
    }
  } catch (err) {
    console.error('Failed to load investigation details', err)
    router.push('/')
  } finally {
    loadingItem.value = null
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.dashboard-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 36px 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.dashboard-header {
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

/* Stat grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}

@media (max-width: 900px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

.stat-card {
  position: relative;
  background: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 12px;
  padding: 20px 22px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.stat-label {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  margin-bottom: 8px;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: var(--text-main);
  line-height: 1.1;
}

.stat-dot {
  position: absolute;
  top: 20px;
  right: 22px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

/* Donut */
.donut-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.donut-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.donut-header h2 {
  font-size: 1.05rem;
  margin: 0;
}

.donut-total {
  font-size: 0.82rem;
  color: var(--text-muted);
}

.donut-body {
  display: flex;
  align-items: center;
  gap: 32px;
  flex-wrap: wrap;
}

.donut {
  width: 160px;
  height: 160px;
  border-radius: 50%;
  position: relative;
  flex-shrink: 0;
  transition: transform 0.4s ease;
}

.donut-hole {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: var(--bg-card);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: inset 0 0 0 1px var(--border-light);
}

.donut-hole-num {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--text-main);
  line-height: 1;
}

.donut-hole-label {
  font-size: 0.72rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-top: 2px;
}

.donut-legend {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-width: 200px;
}

.donut-legend li {
  display: grid;
  grid-template-columns: 14px 1fr auto;
  align-items: center;
  gap: 10px;
  font-size: 0.9rem;
}

.legend-swatch {
  width: 12px;
  height: 12px;
  border-radius: 3px;
}

.swatch-phish { background: var(--verdict-phish); }
.swatch-suspicious { background: var(--verdict-suspicious); }
.swatch-safe { background: var(--verdict-safe); }

.legend-name {
  color: var(--text-main);
}

.legend-value {
  font-weight: 600;
  color: var(--text-main);
}

.legend-pct {
  color: var(--text-muted);
  font-weight: 500;
}

.dot-total { background: var(--accent); }
.dot-phish { background: var(--verdict-phish); }
.dot-suspicious { background: var(--verdict-suspicious); }
.dot-safe { background: var(--verdict-safe); }

/* Recent activity table */
.table-card {
  padding: 0;
  overflow: hidden;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 18px 22px;
  border-bottom: 1px solid var(--border-light);
}

.table-header h2 {
  font-size: 1.05rem;
  font-weight: 600;
  margin: 0;
}

.view-all-link {
  font-size: 0.88rem;
  color: var(--accent);
  text-decoration: none;
  font-weight: 500;
}

.view-all-link:hover {
  text-decoration: underline;
}

.table-responsive {
  width: 100%;
  overflow-x: auto;
}

.history-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.92rem;
}

.history-table th {
  background-color: var(--bg-page);
  padding: 12px 18px;
  font-size: 0.82rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border-light);
}

.history-table td {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border-light);
  color: var(--text-main);
  vertical-align: middle;
}

.history-table tbody tr:last-child td {
  border-bottom: none;
}

.history-table tbody tr:hover {
  background-color: #FAFAFB;
}

.date-cell {
  font-size: 0.85rem;
  color: var(--text-muted);
  white-space: nowrap;
}

.subject-cell {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 500;
}

.sender-cell {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.85rem;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.score-pill {
  font-weight: 600;
}

.actions-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.action-btn {
  padding: 6px 12px;
  font-size: 0.82rem;
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
  max-width: 480px;
}

.start-btn {
  margin-top: 12px;
}
</style>
