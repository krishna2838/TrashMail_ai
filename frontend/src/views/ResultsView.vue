<template>
  <div v-if="store.currentAnalysis" class="results-container">
    <!-- Top Action Bar -->
    <div class="results-top-bar">
      <div class="meta-left">
        <button v-if="isFromBatch" class="back-link-btn" @click="router.push('/batch')">
          <ArrowLeft :size="18" />
          <span>Back to Batch Analysis</span>
        </button>
        <button v-else class="back-link-btn" @click="router.push('/')">
          <ArrowLeft :size="18" />
          <span>Analyze Another Email</span>
        </button>
        <span class="hash-tag mono" :title="store.currentAnalysis.email_hash">
          SHA256: {{ store.currentAnalysis.email_hash?.slice(0, 16) }}...
        </span>
      </div>

      <div class="meta-right">
        <ReportButton :email-hash="store.currentAnalysis.email_hash" />
      </div>
    </div>

    <!-- Main Verdict Card at Top (Simple Mode: Verdict, Risk Meter, Vendor Detection Ratio, 4-Section Explanation) -->
    <VerdictCard :analysis="store.currentAnalysis" :hide-technical="true" />

    <!-- 2-Column Responsive Dashboard Grid (Simple Overview) -->
    <div class="dashboard-grid">
      <!-- Left Column -->
      <div class="dashboard-col">
        <HopTimeline 
          :hops="store.currentAnalysis.hops || []" 
          :originating-ip="store.currentAnalysis.originating_ip || ''"
          :origin-geo="store.currentAnalysis.origin_geo"
          :hide-details="true"
        />

        <GeoMapPanel 
          :origin-geo="store.currentAnalysis.origin_geo" 
          :threat-intel="store.currentAnalysis.threat_intel"
          :hide-details="true"
        />
      </div>

      <!-- Right Column -->
      <div class="dashboard-col">
        <NetworkGraphPanel 
          :email-hash="store.currentAnalysis.email_hash"
          :campaign="store.currentAnalysis.campaign"
        />

        <ChatPanel :context="analysisChatContext" />
      </div>
    </div>

    <!-- Part C — Single Collapsible Section for Full Technical Details -->
    <div class="technical-dossier-card card">
      <div class="technical-toggle-header">
        <div class="tech-header-left">
          <SlidersHorizontal :size="20" class="tech-icon" />
          <div class="tech-titles">
            <h2 class="tech-main-title">Forensic Technical Dossier</h2>
            <p class="tech-sub-title">Complete forensic evidence: authentication anomalies, ML signal weights, cryptographic hashes, raw MTA hop trace & server metadata.</p>
          </div>
        </div>
        <button 
          class="btn-secondary toggle-technical-btn"
          @click="showTechnical = !showTechnical"
        >
          <Code2 :size="15" />
          <span>{{ showTechnical ? 'Hide Technical Details' : `Show Full Technical Details (${technicalSummaryLabel})` }}</span>
          <ChevronUp v-if="showTechnical" :size="16" />
          <ChevronDown v-else :size="16" />
        </button>
      </div>

      <!-- Technical Dossier Body (Expanded) -->
      <div v-show="showTechnical" class="technical-dossier-body">
        <!-- 1. VerdictCard Technical Panels: Indicators, ML Signals Attribution, Case Fingerprints -->
        <VerdictCard :analysis="store.currentAnalysis" :only-technical="true" />

        <!-- 2. Two-column grid for Server Infrastructure Metadata & Full MTA Hop Trace -->
        <div class="technical-subgrid">
          <GeoMapPanel 
            :origin-geo="store.currentAnalysis.origin_geo" 
            :threat-intel="store.currentAnalysis.threat_intel"
            :only-details="true"
          />
          <HopTimeline 
            :hops="store.currentAnalysis.hops || []" 
            :originating-ip="store.currentAnalysis.originating_ip || ''"
            :origin-geo="store.currentAnalysis.origin_geo"
            :only-details="true"
          />
        </div>
      </div>
    </div>
  </div>

  <div v-else class="loading-state-container">
    <div class="spinner spinner-dark"></div>
    <span>Redirecting to analysis dashboard...</span>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ArrowLeft, SlidersHorizontal, Code2, ChevronUp, ChevronDown } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import VerdictCard from '../components/VerdictCard.vue'
import HopTimeline from '../components/HopTimeline.vue'
import GeoMapPanel from '../components/GeoMapPanel.vue'
import NetworkGraphPanel from '../components/NetworkGraphPanel.vue'
import ChatPanel from '../components/ChatPanel.vue'
import ReportButton from '../components/ReportButton.vue'

const router = useRouter()
const route = useRoute()
const store = useAnalysisStore()
const showTechnical = ref(false)

const isFromBatch = computed(() => route.query.fromBatch === 'true')

const analysisChatContext = computed(() => {
  const a = store.currentAnalysis
  if (!a) return null
  return {
    subject: a.subject,
    sender: a.sender,
    verdict: a.verdict,
    risk_score: a.risk_score,
    ml_phishing_probability: a.ml_phishing_probability,
    indicators: a.indicators,
    campaign_size: a.campaign?.campaign_size,
    origin_geo: a.origin_geo ? { country: a.origin_geo.country, city: a.origin_geo.city } : null,
  }
})

const technicalSummaryLabel = computed(() => {
  const a = store.currentAnalysis
  if (!a) return 'indicators, fingerprints, full hop trace'

  const parts = []
  const indCount = a.indicators?.length || 0
  if (indCount > 0) {
    parts.push(`${indCount} indicator${indCount === 1 ? '' : 's'}`)
  }

  const hasFp = Boolean(
    a.upi_ids?.length ||
    a.wallet_addresses?.length ||
    a.attachment_hashes?.length ||
    a.template_structure_hash ||
    a.possible_bank_accounts?.length
  )
  if (hasFp) {
    parts.push('fingerprints')
  }

  const hopCount = a.hops?.length || 0
  if (hopCount > 0) {
    parts.push('full hop trace')
  }

  return parts.join(', ') || 'full forensic dossier'
})

onMounted(() => {
  if (!store.currentAnalysis) {
    router.replace('/')
  }
})
</script>

<style scoped>
.results-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 20px 48px 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.results-top-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}

.meta-left {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}

.back-link-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: none;
  border: none;
  color: var(--accent);
  font-family: var(--font-family);
  font-size: 0.92rem;
  font-weight: 500;
  cursor: pointer;
  padding: 0;
  transition: color 0.15s ease;
}

.back-link-btn:hover {
  color: var(--accent-hover);
  text-decoration: underline;
}

.hash-tag {
  font-size: 0.8rem;
  color: var(--text-muted);
  background-color: var(--bg-card);
  padding: 4px 10px;
  border-radius: 6px;
  box-shadow: var(--card-shadow);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 24px;
  align-items: start;
}

.dashboard-col {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

/* Part C — Technical Dossier Collapsible Card */
.technical-dossier-card {
  display: flex;
  flex-direction: column;
  gap: 20px;
  background-color: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 12px;
  padding: 24px;
}

.technical-toggle-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}

.tech-header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.tech-icon {
  color: var(--accent);
  flex-shrink: 0;
}

.tech-titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.tech-main-title {
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--text-main);
  margin: 0;
}

.tech-sub-title {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin: 0;
  line-height: 1.4;
}

.toggle-technical-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 18px;
  font-size: 0.88rem;
  font-weight: 600;
  cursor: pointer;
  border-radius: 8px;
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  color: var(--text-main);
  transition: all 0.15s ease;
}

.toggle-technical-btn:hover {
  border-color: var(--accent);
  background-color: var(--accent-light);
  color: var(--accent);
}

.technical-dossier-body {
  display: flex;
  flex-direction: column;
  gap: 24px;
  border-top: 1px solid var(--border-light);
  padding-top: 24px;
}

.technical-subgrid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 24px;
  align-items: start;
}

.loading-state-container {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  min-height: 400px;
  color: var(--text-muted);
}

@media (max-width: 900px) {
  .dashboard-grid,
  .technical-subgrid {
    grid-template-columns: 1fr;
  }
}
</style>
