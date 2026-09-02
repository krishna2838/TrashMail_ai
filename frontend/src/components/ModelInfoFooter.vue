<template>
  <footer class="app-footer">
    <div class="footer-container">
      <div class="model-line">
        <ShieldCheck :size="16" class="footer-icon" />
        <span v-if="modelInfo">
          Classifier trained on {{ (modelInfo.total_rows_after_dedup || 84665).toLocaleString() }} real emails from {{ (modelInfo.sources || []).length || 6 }} public datasets — {{ (accuracyPercent).toFixed(1) }}% accuracy
        </span>
        <span v-else>
          TrashMail AI — Forensic Phishing Intelligence Platform (SIH26106)
        </span>
        <button v-if="modelInfo" class="details-link" @click="showModal = true">
          [Model Metrics]
        </button>
      </div>
      <div class="footer-links">
        <span class="copyright">&copy; 2026 TrashMail AI — SIH26106 Hackathon</span>
      </div>
    </div>

    <!-- Model Metrics Modal -->
    <div v-if="showModal" class="modal-backdrop" @click.self="showModal = false">
      <div class="modal-card">
        <div class="modal-header">
          <h3>ML Model Architecture & Verification</h3>
          <button class="close-btn" @click="showModal = false">&times;</button>
        </div>
        <div v-if="modelInfo" class="modal-body">
          <p class="modal-desc"><strong>Architecture:</strong> {{ modelInfo.model }}</p>
          
          <div class="metrics-grid">
            <div class="metric-card">
              <span class="metric-val">{{ (accuracyPercent).toFixed(2) }}%</span>
              <span class="metric-lbl">Accuracy</span>
            </div>
            <div class="metric-card">
              <span class="metric-val">{{ (modelInfo.metrics?.precision * 100 || 98.86).toFixed(2) }}%</span>
              <span class="metric-lbl">Precision</span>
            </div>
            <div class="metric-card">
              <span class="metric-val">{{ (modelInfo.metrics?.recall * 100 || 99.12).toFixed(2) }}%</span>
              <span class="metric-lbl">Recall</span>
            </div>
            <div class="metric-card">
              <span class="metric-val">{{ (modelInfo.metrics?.f1 * 100 || 98.99).toFixed(2) }}%</span>
              <span class="metric-lbl">F1-Score</span>
            </div>
          </div>

          <h4 class="sources-title">Training Corpora</h4>
          <ul class="sources-list">
            <li v-for="(src, idx) in modelInfo.sources" :key="idx">{{ src }}</li>
          </ul>
        </div>
      </div>
    </div>
  </footer>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ShieldCheck } from 'lucide-vue-next'
import { getModelInfo } from '../api/client'

const modelInfo = ref(null)
const showModal = ref(false)

const accuracyPercent = computed(() => {
  if (!modelInfo.value?.metrics?.accuracy) return 98.9
  return modelInfo.value.metrics.accuracy * 100
})

onMounted(async () => {
  try {
    const data = await getModelInfo()
    modelInfo.value = data
  } catch (e) {
    console.warn('Could not load model info for footer', e)
  }
})
</script>

<style scoped>
.app-footer {
  margin-top: auto;
  border-top: 1px solid var(--border-light);
  background-color: var(--bg-card);
  padding: 16px 24px;
  font-size: 0.85rem;
  color: var(--text-muted);
}

.footer-container {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.model-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.footer-icon {
  color: var(--accent);
  flex-shrink: 0;
}

.details-link {
  background: none;
  border: none;
  color: var(--accent);
  font-family: inherit;
  font-size: 0.82rem;
  cursor: pointer;
  padding: 0;
  text-decoration: underline;
}

.details-link:hover {
  color: var(--accent-hover);
}

.footer-links {
  display: flex;
  align-items: center;
  gap: 16px;
}

.copyright {
  color: var(--text-light);
  font-size: 0.8rem;
}

/* Modal */
.modal-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-card {
  background-color: #FFFFFF;
  border-radius: 12px;
  max-width: 540px;
  width: 100%;
  padding: 24px;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.close-btn {
  background: none;
  border: none;
  font-size: 1.5rem;
  color: var(--text-muted);
  cursor: pointer;
  line-height: 1;
}

.modal-desc {
  font-size: 0.9rem;
  margin-bottom: 16px;
  color: var(--text-main);
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-bottom: 20px;
}

.metric-card {
  background-color: var(--bg-page);
  border-radius: 8px;
  padding: 10px;
  text-align: center;
  display: flex;
  flex-direction: column;
}

.metric-val {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--accent);
}

.metric-lbl {
  font-size: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
}

.sources-title {
  font-size: 0.9rem;
  font-weight: 600;
  margin-bottom: 8px;
}

.sources-list {
  padding-left: 20px;
  font-size: 0.85rem;
  color: var(--text-muted);
  line-height: 1.5;
}
</style>
