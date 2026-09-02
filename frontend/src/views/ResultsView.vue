<template>
  <div v-if="store.currentAnalysis" class="results-container">
    <!-- Top Action Bar -->
    <div class="results-top-bar">
      <div class="meta-left">
        <button class="back-link-btn" @click="router.push('/')">
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

    <!-- Main Verdict Card at Top -->
    <VerdictCard :analysis="store.currentAnalysis" />

    <!-- 2-Column Responsive Dashboard Grid -->
    <div class="dashboard-grid">
      <!-- Left Column -->
      <div class="dashboard-col">
        <HopTimeline 
          :hops="store.currentAnalysis.hops || []" 
          :originating-ip="store.currentAnalysis.originating_ip || ''"
        />

        <GeoMapPanel 
          :origin-geo="store.currentAnalysis.origin_geo" 
          :threat-intel="store.currentAnalysis.threat_intel"
        />
      </div>

      <!-- Right Column -->
      <div class="dashboard-col">
        <NetworkGraphPanel 
          :email-hash="store.currentAnalysis.email_hash"
          :campaign="store.currentAnalysis.campaign"
        />

        <ChatPanel />
      </div>
    </div>
  </div>

  <div v-else class="loading-state-container">
    <div class="spinner spinner-dark"></div>
    <span>Redirecting to analysis dashboard...</span>
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import VerdictCard from '../components/VerdictCard.vue'
import HopTimeline from '../components/HopTimeline.vue'
import GeoMapPanel from '../components/GeoMapPanel.vue'
import NetworkGraphPanel from '../components/NetworkGraphPanel.vue'
import ChatPanel from '../components/ChatPanel.vue'
import ReportButton from '../components/ReportButton.vue'

const router = useRouter()
const store = useAnalysisStore()

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

.loading-state-container {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  min-height: 400px;
  color: var(--text-muted);
}

@media (max-width: 900px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}
</style>
