<template>
  <div class="investigations-container">
    <div class="page-header">
      <div class="title-row">
        <FolderSearch :size="26" class="header-icon" />
        <h1>Investigations</h1>
      </div>
      <p class="subtitle">
        All analyzed emails, ranked by risk score.
      </p>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="card loading-card">
      <div class="spinner spinner-dark"></div>
      <span>Loading investigations...</span>
    </div>

    <!-- Empty -->
    <div v-else-if="allItems.length === 0" class="card empty-card">
      <Inbox :size="48" class="empty-icon" />
      <h2>No analyses yet</h2>
      <p class="empty-desc">
        No email investigations have been recorded yet. Submit an email from the Analyze tab to build your forensic audit trail.
      </p>
      <button class="btn-primary start-btn" @click="router.push('/')">
        Analyze an Email Now
      </button>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Controls: search + tabs -->
      <div class="controls-bar">
        <div class="search-wrap">
          <SearchIcon :size="16" class="search-icon" />
          <input
            v-model="searchQuery"
            type="text"
            class="search-input"
            placeholder="Search subject, sender, or domain..."
          />
        </div>

        <div class="filter-tabs">
          <button
            v-for="tab in tabs"
            :key="tab.key"
            :class="['tab-btn', activeTab === tab.key ? 'tab-btn-active' : '']"
            @click="activeTab = tab.key"
          >
            <span>{{ tab.label }}</span>
            <span class="tab-count">{{ tab.count }}</span>
          </button>
        </div>
      </div>

      <!-- Card list -->
      <div v-if="filteredItems.length === 0" class="card empty-card small">
        <p class="empty-desc">No investigations match your filters.</p>
      </div>

      <div v-else class="cards-list">
        <div
          v-for="item in filteredItems"
          :key="item.id || item.email_hash"
          class="inv-card"
        >
          <!-- Top row: risk bar + verdict + linked chip + view btn -->
          <div class="card-top">
            <div class="risk-block">
              <div class="risk-header">
                <span class="risk-label">Risk</span>
                <span class="risk-score" :style="{ color: getVerdictColor(item.verdict) }">
                  {{ item.risk_score }}/100
                </span>
              </div>
              <div class="meter-track">
                <div
                  class="meter-fill"
                  :style="{ width: `${clampScore(item.risk_score)}%`, backgroundImage: riskGradient(item.risk_score) }"
                ></div>
              </div>
            </div>

            <div class="right-block">
              <span :class="['badge', getVerdictBadgeClass(item.verdict)]">
                {{ item.verdict }}
              </span>
              <span v-if="item.campaign_size > 0" class="linked-chip" :title="`Linked to ${item.campaign_size} other analyzed ${item.campaign_size === 1 ? 'email' : 'emails'} via shared infrastructure`">
                <LinkIcon :size="12" />
                Linked to {{ item.campaign_size }} {{ item.campaign_size === 1 ? 'other' : 'others' }}
              </span>
              <button
                class="btn-secondary action-btn"
                :disabled="loadingItem === (item.id || item.email_hash)"
                @click="viewAnalysis(item)"
              >
                <Eye :size="14" />
                <span>View</span>
              </button>
            </div>
          </div>

          <!-- Subject + sender -->
          <div class="subject" :title="item.subject">{{ item.subject }}</div>
          <div class="sender mono" :title="item.sender">{{ item.sender }}</div>

          <!-- Meta row: timestamp + indicator pills -->
          <div class="meta-row">
            <span class="timestamp">
              <Clock :size="12" />
              {{ formatDate(item.analyzed_at) }}
            </span>
            <div class="pills">
              <span v-if="item.top_domain" class="pill" :title="`Top domain: ${item.top_domain}`">
                <span class="pill-label">Domain</span>
                <span class="pill-value mono">{{ item.top_domain }}</span>
              </span>
              <span v-if="item.origin_country" class="pill" :title="`Origin: ${item.origin_country}`">
                <span class="pill-label">Origin</span>
                <span class="pill-value">{{ item.origin_country }}</span>
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
  FolderSearch, Inbox, Eye, Clock,
  Search as SearchIcon, Link as LinkIcon,
} from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import { getHistory, getHistoryItem } from '../api/client'
import { riskGradient } from '../utils/riskGradient'

const router = useRouter()
const store = useAnalysisStore()

const allItems = ref([])
const loading = ref(true)
const loadingItem = ref(null)
const searchQuery = ref('')
const activeTab = ref('all')

function bucket(score) {
  if (score >= 85) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 35) return 'medium'
  return 'safe'
}

function clampScore(s) {
  const n = Number(s) || 0
  return Math.max(0, Math.min(100, n))
}

function formatDate(isoStr) {
  if (!isoStr) return 'Just now'
  try { return new Date(isoStr).toLocaleString() } catch { return isoStr }
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

// Sort loaded list by risk_score desc for the "ranked by risk" subtitle
const sortedItems = computed(() =>
  [...allItems.value].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
)

const searchedItems = computed(() => {
  const q = searchQuery.value.trim().toLowerCase()
  if (!q) return sortedItems.value
  return sortedItems.value.filter((it) => {
    const subject = (it.subject || '').toLowerCase()
    const sender = (it.sender || '').toLowerCase()
    const domain = (it.top_domain || '').toLowerCase()
    return subject.includes(q) || sender.includes(q) || domain.includes(q)
  })
})

const tabs = computed(() => {
  const counts = { all: 0, critical: 0, high: 0, medium: 0, safe: 0 }
  for (const it of searchedItems.value) {
    counts.all += 1
    counts[bucket(it.risk_score || 0)] += 1
  }
  return [
    { key: 'all', label: 'All', count: counts.all },
    { key: 'critical', label: 'Critical', count: counts.critical },
    { key: 'high', label: 'High', count: counts.high },
    { key: 'medium', label: 'Medium', count: counts.medium },
    { key: 'safe', label: 'Safe', count: counts.safe },
  ]
})

const filteredItems = computed(() => {
  if (activeTab.value === 'all') return searchedItems.value
  return searchedItems.value.filter((it) => bucket(it.risk_score || 0) === activeTab.value)
})

async function loadHistory() {
  loading.value = true
  try {
    const data = await getHistory(50)
    if (data && Array.isArray(data) && data.length > 0) {
      allItems.value = data
    } else {
      allItems.value = store.history || []
    }
  } catch (err) {
    console.warn('Could not fetch history from backend, using local cache', err)
    allItems.value = store.history || []
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
.investigations-container {
  max-width: 1100px;
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

/* Controls */
.controls-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  justify-content: space-between;
}

.search-wrap {
  position: relative;
  flex: 1;
  min-width: 260px;
  max-width: 420px;
}

.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-muted);
}

.search-input {
  width: 100%;
  padding: 10px 12px 10px 36px;
  border: 1px solid var(--border-light);
  background: var(--bg-card);
  border-radius: 8px;
  font-size: 0.92rem;
  color: var(--text-main);
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.search-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-light);
}

.filter-tabs {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.tab-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border: 1px solid var(--border-light);
  background: var(--bg-card);
  border-radius: 8px;
  font-size: 0.86rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s ease;
}

.tab-btn:hover {
  color: var(--text-main);
  background: var(--bg-page);
}

.tab-btn-active {
  color: var(--accent);
  background: var(--accent-light);
  border-color: var(--accent);
  font-weight: 600;
}

.tab-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 22px;
  height: 20px;
  padding: 0 6px;
  border-radius: 9999px;
  background: rgba(0, 0, 0, 0.06);
  font-size: 0.75rem;
  font-weight: 600;
}

.tab-btn-active .tab-count {
  background: var(--accent);
  color: #fff;
}

/* Cards list */
.cards-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.inv-card {
  background: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 12px;
  padding: 18px 20px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
  display: flex;
  flex-direction: column;
  gap: 10px;
  transition: box-shadow 0.18s ease, border-color 0.15s ease, transform 0.18s ease;
}

.inv-card:hover {
  border-color: var(--accent-light);
  box-shadow: 0 6px 14px rgba(15, 23, 42, 0.08), 0 2px 4px rgba(29, 78, 216, 0.06);
  transform: translateY(-2px);
}

.card-top {
  display: flex;
  align-items: center;
  gap: 20px;
  justify-content: space-between;
  flex-wrap: wrap;
}

.risk-block {
  flex: 1;
  min-width: 200px;
  max-width: 360px;
}

.risk-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 6px;
}

.risk-label {
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}

.risk-score {
  font-size: 0.95rem;
  font-weight: 700;
}

.meter-track {
  width: 100%;
  height: 8px;
  background-color: var(--border-light);
  border-radius: 9999px;
  overflow: hidden;
}

.meter-fill {
  height: 100%;
  border-radius: 9999px;
  transition: width 0.4s ease;
}

.right-block {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.linked-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 9999px;
  background: var(--accent-light);
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 600;
  border: 1px solid rgba(29, 78, 216, 0.2);
}

.action-btn {
  padding: 6px 12px;
  font-size: 0.82rem;
}

.subject {
  font-weight: 600;
  color: var(--text-main);
  font-size: 1rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sender {
  color: var(--text-muted);
  font-size: 0.85rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.meta-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  padding-top: 6px;
  border-top: 1px dashed var(--border-light);
}

.timestamp {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 0.78rem;
  color: var(--text-muted);
}

.pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 9999px;
  background: #F1F3F5;
  color: var(--text-muted);
  font-size: 0.75rem;
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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
  padding: 32px 20px;
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
