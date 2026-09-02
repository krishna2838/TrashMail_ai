<template>
  <div class="app-layout">
    <!-- Top Navigation Header -->
    <header class="app-navbar">
      <div class="nav-container">
        <router-link to="/" class="nav-brand">
          <ShieldAlert :size="24" class="brand-shield" />
          <span class="brand-title">TraceMail <span class="brand-ai">AI</span></span>
        </router-link>

        <nav class="nav-links">
          <router-link to="/" class="nav-link" active-class="nav-link-active" exact>
            <Search :size="16" />
            <span>Analyze</span>
          </router-link>

          <router-link 
            to="/results" 
            :class="['nav-link', !store.hasAnalysis ? 'nav-link-disabled' : '']" 
            active-class="nav-link-active"
          >
            <BarChart2 :size="16" />
            <span>Results</span>
            <span v-if="store.hasAnalysis" :class="['dot-indicator', store.verdictClass]"></span>
          </router-link>

          <router-link to="/batch" class="nav-link" active-class="nav-link-active">
            <Layers :size="16" />
            <span>Batch Analyze</span>
          </router-link>

          <router-link to="/history" class="nav-link" active-class="nav-link-active">
            <History :size="16" />
            <span>History</span>
          </router-link>
        </nav>
      </div>
    </header>

    <!-- Main View Outlet -->
    <main class="main-content">
      <router-view />
    </main>

    <!-- Unobtrusive Model Info Footer -->
    <ModelInfoFooter />
  </div>
</template>

<script setup>
import { ShieldAlert, Search, BarChart2, Layers, History } from 'lucide-vue-next'
import { useAnalysisStore } from './stores/analysis'
import ModelInfoFooter from './components/ModelInfoFooter.vue'

const store = useAnalysisStore()
</script>

<style scoped>
.app-layout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.app-navbar {
  background-color: var(--bg-card);
  border-bottom: 1px solid var(--border-light);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
  position: sticky;
  top: 0;
  z-index: 100;
}

.nav-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 24px;
  height: 64px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.nav-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--text-main);
  text-decoration: none;
}

.brand-shield {
  color: var(--accent);
}

.brand-title {
  font-size: 1.25rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.brand-ai {
  color: var(--accent);
  font-weight: 800;
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 8px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 0.92rem;
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

.nav-link-disabled {
  opacity: 0.5;
  pointer-events: none;
}

.dot-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-left: 2px;
}

.main-content {
  flex: 1;
  width: 100%;
}
</style>
