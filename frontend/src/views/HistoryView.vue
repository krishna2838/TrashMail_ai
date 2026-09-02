<template>
  <div class="history-container">
    <div class="history-header">
      <div class="title-row">
        <HistoryIcon :size="26" class="header-icon" />
        <h1>Investigation History</h1>
      </div>
      <p class="subtitle">
        Persistent forensic audit trail of analyzed email messages and threat scoring results.
      </p>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="card loading-card">
      <div class="spinner spinner-dark"></div>
      <span>Loading investigation history from database...</span>
    </div>

    <!-- History Table -->
    <div v-else-if="historyList && historyList.length > 0" class="card table-card">
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
            <tr v-for="item in historyList" :key="item.id || item.email_hash">
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
                <a 
                  :href="getReportUrl(item.id || item.email_hash)" 
                  target="_blank" 
                  class="btn-secondary action-btn pdf-btn"
                  title="Download Forensic PDF Report"
                >
                  <FileText :size="14" />
                  <span>PDF</span>
                </a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Empty State -->
    <div v-else class="card empty-card">
      <Inbox :size="48" class="empty-icon" />
      <h2>No Prior Investigations Found</h2>
      <p class="empty-desc">
        No email investigations have been recorded in the database yet. Submit an email from the Analyze tab to build your forensic audit trail.
      </p>
      <button class="btn-primary start-btn" @click="router.push('/')">
        Analyze an Email Now
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { History as HistoryIcon, Inbox, Eye, FileText } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import { getHistory, getHistoryItem, getReportUrl } from '../api/client'

const router = useRouter()
const store = useAnalysisStore()

const historyList = ref([])
const loading = ref(true)
const loadingItem = ref(null)

function formatDate(isoStr) {
  if (!isoStr) return 'Just now'
  try {
    const d = new Date(isoStr)
    return d.toLocaleString()
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
      // Fallback to local store history if API returns empty
      historyList.value = store.history || []
    }
  } catch (err) {
    console.warn('Could not fetch history from backend API, falling back to local cache', err)
    historyList.value = store.history || []
  } finally {
    loading.value = false
  }
}

async function viewAnalysis(item) {
  const hash = item.id || item.email_hash
  if (!hash) return

  // If already loaded in store
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

onMounted(() => {
  loadHistory()
})
</script>

<style scoped>
.history-container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 36px 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.history-header {
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

.table-card {
  padding: 0;
  overflow: hidden;
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

.pdf-btn {
  color: var(--accent);
  text-decoration: none;
}

.pdf-btn:hover {
  background-color: var(--accent-light);
  border-color: var(--accent);
}

/* Empty State Card */
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
