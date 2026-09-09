<template>
  <aside class="app-sidebar">
    <router-link to="/" class="brand" exact-active-class="brand-active">
      <ShieldAlert :size="24" class="brand-shield" />
      <span class="brand-title">TraceMail <span class="brand-ai">AI</span></span>
    </router-link>

    <div class="section-label">Operations</div>

    <nav class="nav-list">
      <router-link to="/dashboard" class="nav-link" active-class="nav-link-active">
        <LayoutGrid :size="18" />
        <span>Dashboard</span>
      </router-link>

      <router-link
        to="/"
        class="nav-link"
        active-class="nav-link-active-noop"
        exact-active-class="nav-link-active"
      >
        <Search :size="18" />
        <span>Analyze</span>
      </router-link>

      <router-link to="/batch" class="nav-link" active-class="nav-link-active">
        <Layers :size="18" />
        <span>Batch Analyze</span>
      </router-link>

      <router-link to="/history" class="nav-link" active-class="nav-link-active">
        <Clock :size="18" />
        <span>History</span>
      </router-link>

      <router-link to="/clusters" class="nav-link" active-class="nav-link-active">
        <Share2 :size="18" />
        <span>Clusters</span>
      </router-link>

      <router-link to="/reports" class="nav-link" active-class="nav-link-active">
        <FileText :size="18" />
        <span>Reports</span>
      </router-link>

      <router-link
        to="/results"
        :class="['nav-link', !store.hasAnalysis ? 'nav-link-disabled' : '']"
        active-class="nav-link-active"
      >
        <BarChart2 :size="18" />
        <span>Results</span>
        <span v-if="store.hasAnalysis" :class="['dot-indicator', store.verdictClass]"></span>
      </router-link>
    </nav>
  </aside>
</template>

<script setup>
import { ShieldAlert, LayoutGrid, Search, Layers, Clock, BarChart2, Share2, FileText } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'

const store = useAnalysisStore()
</script>

<style scoped>
.app-sidebar {
  width: 240px;
  flex-shrink: 0;
  background-color: var(--bg-card);
  border-right: 1px solid var(--border-light);
  min-height: 100vh;
  position: sticky;
  top: 0;
  display: flex;
  flex-direction: column;
  padding: 20px 0 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 20px 20px;
  color: var(--text-main);
  text-decoration: none;
  border-bottom: 1px solid var(--border-light);
  margin-bottom: 16px;
}

.brand-shield {
  color: var(--accent);
}

.brand-title {
  font-size: 1.15rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.brand-ai {
  color: var(--accent);
  font-weight: 800;
}

.section-label {
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
  padding: 4px 20px 8px;
  font-weight: 600;
}

.nav-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 0 12px;
}

.nav-link {
  position: relative;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 0.93rem;
  font-weight: 500;
  color: var(--text-muted);
  text-decoration: none;
  transition: all 0.15s ease;
}

.nav-link:hover {
  color: var(--text-main);
  background-color: var(--bg-page);
}

.nav-link-active {
  color: var(--accent) !important;
  background-color: var(--accent-light) !important;
  font-weight: 600;
}

.nav-link-active::before {
  content: '';
  position: absolute;
  left: -12px;
  top: 6px;
  bottom: 6px;
  width: 3px;
  border-radius: 0 3px 3px 0;
  background-color: var(--accent);
}

.nav-link-disabled {
  opacity: 0.5;
  pointer-events: none;
}

.dot-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-left: auto;
}

@media print {
  .app-sidebar {
    display: none !important;
  }
}
</style>
