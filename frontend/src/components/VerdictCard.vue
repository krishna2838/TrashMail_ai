<template>
  <div class="card verdict-card">
    <div class="verdict-header">
      <div class="verdict-summary">
        <span class="label-heading">Email Forensic Verdict</span>
        <div class="verdict-title-row">
          <h1 class="verdict-title">{{ analysis.verdict }}</h1>
          <span :class="['badge', verdictBadgeClass]">
            <component :is="verdictIcon" :size="16" />
            {{ analysis.verdict }}
          </span>
        </div>
        <p class="subject-line"><strong>Subject:</strong> {{ analysis.subject || '(No subject provided)' }}</p>
        <p class="sender-line"><strong>From:</strong> {{ analysis.sender || 'Unknown' }}</p>
      </div>

      <div class="score-container">
        <div class="score-display">
          <span class="score-number" :style="{ color: verdictColor }">{{ analysis.risk_score }}</span>
          <span class="score-max">/ 100</span>
        </div>
        <span class="score-label">Composite Threat Risk</span>
        <div class="meter-track">
          <div 
            class="meter-fill" 
            :style="{ width: `${analysis.risk_score}%`, backgroundColor: verdictColor }"
          ></div>
        </div>
      </div>
    </div>

    <!-- Threat Indicators List -->
    <div class="indicators-section">
      <h3 class="section-subtitle">Identified Indicators & Anomalies</h3>
      <div v-if="analysis.indicators && analysis.indicators.length > 0" class="indicators-list">
        <div v-for="(indicator, idx) in analysis.indicators" :key="idx" class="indicator-item">
          <AlertTriangle :size="18" class="indicator-icon" />
          <span>{{ indicator }}</span>
        </div>
      </div>
      <div v-else class="no-indicators">
        <CheckCircle :size="18" class="safe-icon" />
        <span>No malicious indicators or header anomalies were detected.</span>
      </div>
    </div>

    <!-- Explain Findings Button & Inline Expandable Panel -->
    <div class="explain-section">
      <button 
        class="btn-secondary explain-btn"
        :disabled="isExplaining"
        @click="toggleExplain"
      >
        <HelpCircle :size="18" />
        <span>{{ isExpanded ? 'Hide Plain-Language Explanation' : 'Explain this in plain language' }}</span>
        <div v-if="isExplaining" class="spinner spinner-dark"></div>
        <ChevronUp v-else-if="isExpanded" :size="18" />
        <ChevronDown v-else :size="18" />
      </button>

      <div v-if="isExpanded" class="explanation-panel">
        <div v-if="isExplaining" class="explaining-loading">
          <div class="spinner spinner-dark"></div>
          <span>Consulting local AI assistant for plain-language briefing...</span>
        </div>
        <div v-else-if="explainError" class="explanation-error">
          <AlertTriangle :size="18" />
          <span>{{ explainError }}</span>
        </div>
        <div v-else-if="explanationText" class="explanation-content">
          <p v-for="(para, pIdx) in formattedParagraphs" :key="pIdx">{{ para }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { AlertTriangle, CheckCircle, HelpCircle, ChevronDown, ChevronUp } from 'lucide-vue-next'
import { chatExplain } from '../api/client'

const props = defineProps({
  analysis: {
    type: Object,
    required: true,
  },
})

const isExpanded = ref(false)
const isExplaining = ref(false)
const explanationText = ref('')
const explainError = ref(null)

const verdictColor = computed(() => {
  const v = props.analysis.verdict
  if (v === 'Safe') return 'var(--verdict-safe)'
  if (v === 'Suspicious') return 'var(--verdict-suspicious)'
  return 'var(--verdict-phish)'
})

const verdictBadgeClass = computed(() => {
  const v = props.analysis.verdict
  if (v === 'Safe') return 'badge-safe'
  if (v === 'Suspicious') return 'badge-suspicious'
  return 'badge-phish'
})

const verdictIcon = computed(() => {
  return props.analysis.verdict === 'Safe' ? CheckCircle : AlertTriangle
})

const formattedParagraphs = computed(() => {
  if (!explanationText.value) return []
  return explanationText.value.split('\n\n').filter(p => p.trim())
})

async function toggleExplain() {
  if (isExpanded.value) {
    isExpanded.value = false
    return
  }

  isExpanded.value = true

  // If already fetched, don't re-fetch
  if (explanationText.value) return

  isExplaining.value = true
  explainError.value = null

  try {
    const res = await chatExplain(props.analysis.email_hash, props.analysis)
    explanationText.value = res.explanation
  } catch (err) {
    console.error('Explain failed', err)
    explainError.value = err.response?.data?.detail || 'AI chat assistant is currently unavailable.'
  } finally {
    isExplaining.value = false
  }
}
</script>

<style scoped>
.verdict-card {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.verdict-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}

.verdict-summary {
  flex: 1;
  min-width: 280px;
}

.label-heading {
  font-size: 0.85rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
}

.verdict-title-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 6px 0 12px 0;
}

.verdict-title {
  font-size: 2rem;
  font-weight: 700;
  color: var(--text-main);
}

.subject-line, .sender-line {
  font-size: 0.95rem;
  color: var(--text-muted);
  margin-bottom: 4px;
  word-break: break-all;
}

.subject-line strong, .sender-line strong {
  color: var(--text-main);
}

.score-container {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  min-width: 220px;
}

.score-display {
  display: flex;
  align-items: baseline;
  gap: 4px;
}

.score-number {
  font-size: 3rem;
  font-weight: 700;
  line-height: 1;
}

.score-max {
  font-size: 1.1rem;
  font-weight: 500;
  color: var(--text-light);
}

.score-label {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin-top: 4px;
  margin-bottom: 8px;
}

.meter-track {
  width: 100%;
  height: 10px;
  background-color: var(--border-light);
  border-radius: 9999px;
  overflow: hidden;
}

.meter-fill {
  height: 100%;
  border-radius: 9999px;
  transition: width 0.6s ease;
}

/* Indicators */
.indicators-section {
  border-top: 1px solid var(--border-light);
  padding-top: 20px;
}

.section-subtitle {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 12px;
}

.indicators-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.indicator-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  font-size: 0.95rem;
  color: var(--text-main);
}

.indicator-icon {
  color: var(--verdict-phish);
  flex-shrink: 0;
  margin-top: 2px;
}

.no-indicators {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--verdict-safe);
  font-size: 0.95rem;
}

.safe-icon {
  color: var(--verdict-safe);
  flex-shrink: 0;
}

/* Explain Section */
.explain-section {
  border-top: 1px solid var(--border-light);
  padding-top: 16px;
}

.explain-btn {
  width: 100%;
  justify-content: center;
  padding: 10px 16px;
}

.explanation-panel {
  margin-top: 16px;
  background-color: var(--bg-page);
  border-radius: 8px;
  padding: 16px 20px;
  font-size: 0.95rem;
  line-height: 1.6;
}

.explaining-loading {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--text-muted);
}

.explanation-error {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--verdict-phish);
}

.explanation-content p {
  margin-bottom: 10px;
}

.explanation-content p:last-child {
  margin-bottom: 0;
}

@media (max-width: 640px) {
  .score-container {
    align-items: flex-start;
  }
}
</style>
