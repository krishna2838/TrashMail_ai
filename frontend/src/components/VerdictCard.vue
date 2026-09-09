<template>
  <div :class="['card', 'verdict-card', { 'technical-card': onlyTechnical }]">
    <!-- Top Verdict Header (Hidden in onlyTechnical mode) -->
    <div v-if="!onlyTechnical" class="verdict-header">
      <div class="verdict-summary">
        <span class="label-heading">Email Security Verdict</span>
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
        <span class="score-label">
          Composite Threat Risk
          <span class="abbr-help" title="A weighted risk score from 0 to 100 combining ML classification, authentication header anomalies, and threat intelligence.">(?)</span>
        </span>
        <div class="meter-track">
          <div 
            class="meter-fill" 
            :style="{ width: `${analysis.risk_score}%`, backgroundColor: verdictColor }"
          ></div>
        </div>
      </div>
    </div>

    <!-- Detection Ratio Badge (Part B — VirusTotal, Hidden in onlyTechnical mode) -->
    <div v-if="!onlyTechnical && detectionRatio" class="detection-ratio-section">
      <div :class="['detection-badge', detectionBadgeClass]">
        <span class="detection-count">{{ detectionRatio.malicious }}</span>
        <span class="detection-sep">/</span>
        <span class="detection-total">{{ detectionRatio.total }}</span>
      </div>
      <span class="detection-label">
        security vendors flagged this IP malicious
        <span class="abbr-help" title="Based on VirusTotal threat intelligence scanning of the originating public mail server IP.">(?)</span>
      </span>
    </div>

    <!-- Threat Indicators List (Technical: hidden when hideTechnical is true) -->
    <div v-if="!hideTechnical" class="indicators-section">
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

    <!-- Model Feature Attribution / Top Phrases (Technical: hidden when hideTechnical is true) -->
    <div v-if="!hideTechnical && hasTopPhrases" class="model-explain-section">
      <button 
        type="button" 
        class="explain-toggle-btn"
        @click="isPhrasesExpanded = !isPhrasesExpanded"
      >
        <div class="explain-toggle-left">
          <Brain :size="16" class="explain-icon" />
          <h3 class="section-subtitle explain-subtitle">
            {{ isPhishingLeaning ? 'Why the model flagged this' : 'What looked legitimate' }}
          </h3>
          <span class="explain-count-badge">{{ analysis.top_phrases.length }} signals</span>
        </div>
        <ChevronUp v-if="isPhrasesExpanded" :size="16" class="toggle-chevron" />
        <ChevronDown v-else :size="16" class="toggle-chevron" />
      </button>

      <div v-show="isPhrasesExpanded" class="explain-body">
        <p class="explain-hint">
          {{ isPhishingLeaning 
            ? 'Key words and phrases that pushed the ML classifier toward a phishing verdict:' 
            : 'Key words and phrases that pushed the ML classifier toward a legitimate verdict:' 
          }}
        </p>
        <div class="phrase-chips-grid">
          <div 
            v-for="(item, idx) in analysis.top_phrases" 
            :key="idx" 
            :class="['phrase-chip', item.contribution > 0 ? 'chip-phish' : 'chip-legit']"
            :style="getPhraseStyle(item)"
          >
            <span class="phrase-text">"{{ item.phrase }}"</span>
            <span class="phrase-score">
              {{ item.contribution > 0 ? `+${item.contribution}` : item.contribution }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Extracted Case Fingerprints (Technical: hidden when hideTechnical is true) -->
    <div v-if="!hideTechnical && hasFingerprints" class="fingerprints-section">
      <h3 class="section-subtitle">Extracted Case Fingerprints</h3>
      <div class="fingerprints-grid">
        <!-- UPI IDs -->
        <div v-if="analysis.upi_ids && analysis.upi_ids.length > 0" class="fp-group">
          <span class="fp-label"><CreditCard :size="14" /> UPI Handles</span>
          <div class="fp-tags">
            <span v-for="(upi, idx) in analysis.upi_ids" :key="idx" class="fp-tag fp-upi">
              {{ upi }}
            </span>
          </div>
        </div>

        <!-- Crypto Wallets -->
        <div v-if="analysis.wallet_addresses && analysis.wallet_addresses.length > 0" class="fp-group">
          <span class="fp-label"><Coins :size="14" /> Crypto Wallets</span>
          <div class="fp-tags">
            <span v-for="(wallet, idx) in analysis.wallet_addresses" :key="idx" class="fp-tag fp-wallet" :title="wallet">
              {{ wallet }}
            </span>
          </div>
        </div>

        <!-- Bank Accounts -->
        <div v-if="analysis.possible_bank_accounts && analysis.possible_bank_accounts.length > 0" class="fp-group">
          <span class="fp-label"><Landmark :size="14" /> Possible Bank Accounts</span>
          <div class="fp-tags">
            <span v-for="(acc, idx) in analysis.possible_bank_accounts" :key="idx" class="fp-tag fp-bank">
              {{ acc }}
            </span>
          </div>
        </div>

        <!-- Attachment Content Hashes -->
        <div v-if="analysis.attachment_hashes && analysis.attachment_hashes.length > 0" class="fp-group">
          <span class="fp-label"><FileCode :size="14" /> Attachment SHA-256</span>
          <div class="fp-tags">
            <span v-for="(ahash, idx) in analysis.attachment_hashes" :key="idx" class="fp-tag fp-hash" :title="ahash">
              {{ ahash.slice(0, 16) }}...
            </span>
          </div>
        </div>

        <!-- HTML Template Skeleton Hash -->
        <div v-if="analysis.template_structure_hash" class="fp-group">
          <span class="fp-label"><LayoutTemplate :size="14" /> Template Skeleton Hash</span>
          <div class="fp-tags">
            <span class="fp-tag fp-template" :title="analysis.template_structure_hash">
              {{ analysis.template_structure_hash.slice(0, 16) }}...
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Attachment Intelligence (Technical: hidden when hideTechnical is true) -->
    <AttachmentIntelligencePanel
      v-if="!hideTechnical && hasAttachments"
      :emailHashes="emailHashList"
    />
    <!-- Explain Findings Button & Inline Expandable Panel (Simple: hidden in onlyTechnical mode) -->
    <div v-if="!onlyTechnical" class="explain-section">
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
        <div v-else-if="explanationText" class="explanation-content" v-html="renderedExplanation"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  CreditCard,
  Coins,
  Landmark,
  FileCode,
  LayoutTemplate,
  Brain,
  Shield,
} from 'lucide-vue-next'
import { marked } from 'marked'
import { chatExplain } from '../api/client'
import AttachmentIntelligencePanel from './AttachmentIntelligencePanel.vue'

// Configure marked for safe defaults
marked.setOptions({
  breaks: true,
  gfm: true,
})

const props = defineProps({
  analysis: {
    type: Object,
    required: true,
  },
  hideTechnical: {
    type: Boolean,
    default: false,
  },
  onlyTechnical: {
    type: Boolean,
    default: false,
  },
})

const isExpanded = ref(true)
const isExplaining = ref(false)
const explanationText = ref('')
const explainError = ref(null)
const isPhrasesExpanded = ref(true)

const hasTopPhrases = computed(() => {
  return Boolean(props.analysis?.top_phrases && props.analysis.top_phrases.length > 0)
})

const hasAttachments = computed(() => {
  return Boolean(props.analysis?.attachment_hashes && props.analysis.attachment_hashes.length > 0)
})

const emailHashList = computed(() => {
  const selfHash = props.analysis?.email_hash
  if (!selfHash) return []
  const related = (props.analysis?.campaign?.related_emails || []).map(r => r.id)
  return [selfHash, ...related].filter(Boolean)
})

const isPhishingLeaning = computed(() => {
  return (props.analysis?.ml_phishing_probability ?? 0) >= 0.5
})

function getPhraseStyle(item) {
  const abs = Math.min(Math.abs(item.contribution || 0), 2.0)
  // Subtle scaling: font size from 0.84rem to 0.96rem, slightly stronger border
  const size = 0.84 + (abs / 2.0) * 0.12
  return {
    fontSize: `${size.toFixed(2)}rem`,
  }
}

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

const hasFingerprints = computed(() => {
  const a = props.analysis
  if (!a) return false
  return Boolean(
    (a.upi_ids && a.upi_ids.length > 0) ||
    (a.wallet_addresses && a.wallet_addresses.length > 0) ||
    (a.possible_bank_accounts && a.possible_bank_accounts.length > 0) ||
    (a.attachment_hashes && a.attachment_hashes.length > 0) ||
    a.template_structure_hash
  )
})

const renderedExplanation = computed(() => {
  if (!explanationText.value) return ''
  let html = marked.parse(explanationText.value)
  const glossary = [
    { regex: /\bSPF\b/g, title: 'Sender Policy Framework: verifies the sender IP is authorized to send for this domain' },
    { regex: /\bDKIM\b/g, title: 'DomainKeys Identified Mail: a cryptographic signature proving the email was not altered in transit' },
    { regex: /\bDMARC\b/g, title: 'Domain-based Message Authentication: policy enforcing SPF and DKIM checks' },
    { regex: /\bMTA\b/g, title: 'Mail Transfer Agent: an intermediate server routing email across the internet' },
    { regex: /\bASN\b/g, title: 'Autonomous System Number: identifies the network operator hosting the server' },
  ]
  for (const item of glossary) {
    html = html.replace(item.regex, `<abbr title="${item.title}">$&</abbr>`)
  }
  return html
})

// Part B — Detection ratio from threat_intel
const detectionRatio = computed(() => {
  const ti = props.analysis?.threat_intel
  if (!ti || typeof ti !== 'object') return null
  const ipRep = ti.originating_ip_reputation
  if (!ipRep || !ipRep.available) return null
  const malicious = ipRep.malicious ?? 0
  const harmless = ipRep.harmless ?? 0
  const suspicious = ipRep.suspicious ?? 0
  const undetected = ipRep.undetected ?? 0
  const total = malicious + harmless + suspicious + undetected
  if (total === 0) return null
  return { malicious, total }
})

const detectionBadgeClass = computed(() => {
  if (!detectionRatio.value) return ''
  const ratio = detectionRatio.value.malicious / detectionRatio.value.total
  if (ratio >= 0.1) return 'detection-danger'
  if (ratio > 0) return 'detection-warn'
  return 'detection-clean'
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

onMounted(() => {
  if (!props.onlyTechnical && !explanationText.value && !isExplaining.value) {
    toggleExplain()
  }
})
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

/* Model Feature Attribution Section (Phase 11) */
.model-explain-section {
  border-top: 1px solid var(--border-light);
  padding-top: 18px;
}

.explain-toggle-btn {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  text-align: left;
}

.explain-toggle-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.explain-icon {
  color: var(--accent);
}

.explain-subtitle {
  margin-bottom: 0 !important;
  color: var(--text-main);
  font-size: 0.98rem;
  font-weight: 600;
}

.explain-count-badge {
  font-size: 0.75rem;
  background-color: var(--bg-page);
  color: var(--text-muted);
  border: 1px solid var(--border-light);
  padding: 2px 8px;
  border-radius: 9999px;
  font-weight: 500;
}

.toggle-chevron {
  color: var(--text-muted);
}

.explain-body {
  margin-top: 10px;
}

.explain-hint {
  font-size: 0.84rem;
  color: var(--text-muted);
  margin-bottom: 10px;
}

.phrase-chips-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.phrase-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 6px;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.phrase-chip:hover {
  transform: translateY(-1px);
}

.chip-phish {
  background-color: #FEF2F2;
  color: #DC2626;
  border: 1px solid #FECACA;
}

.chip-legit {
  background-color: #F0FDF4;
  color: #16A34A;
  border: 1px solid #BBF7D0;
}

.phrase-text {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 600;
}

.phrase-score {
  font-size: 0.75rem;
  opacity: 0.85;
  font-weight: 500;
  padding: 1px 4px;
  border-radius: 3px;
  background: rgba(0, 0, 0, 0.05);
}

/* Fingerprints Section (Phase 9) */
.fingerprints-section {
  border-top: 1px solid var(--border-light);
  padding-top: 16px;
}

.fingerprints-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 8px;
}

.fp-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.fp-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.fp-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.fp-tag {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.82rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 500;
}

.fp-upi {
  background-color: #F5F3FF;
  color: #7C3AED;
  border: 1px solid #DDD6FE;
}

.fp-wallet {
  background-color: #FFFBEB;
  color: #D97706;
  border: 1px solid #FDE68A;
}

.fp-bank {
  background-color: #F0FDF4;
  color: #15803D;
  border: 1px solid #BBF7D0;
}

.fp-hash {
  background-color: #FFF1F2;
  color: #E11D48;
  border: 1px solid #FECDD3;
}

.fp-template {
  background-color: #F0FDFA;
  color: #0D9488;
  border: 1px solid #99F6E4;
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

/* Rendered markdown in explanation */
.explanation-content :deep(p) {
  margin: 0 0 10px 0;
}

.explanation-content :deep(p:last-child) {
  margin-bottom: 0;
}

.explanation-content :deep(h1),
.explanation-content :deep(h2),
.explanation-content :deep(h3),
.explanation-content :deep(h4) {
  font-size: 0.92rem;
  font-weight: 700;
  color: var(--text-main);
  margin: 14px 0 6px 0;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border-light);
}

.explanation-content :deep(h1:first-child),
.explanation-content :deep(h2:first-child),
.explanation-content :deep(h3:first-child),
.explanation-content :deep(h4:first-child) {
  margin-top: 0;
}

.explanation-content :deep(ul),
.explanation-content :deep(ol) {
  margin: 4px 0 10px 0;
  padding-left: 20px;
}

.explanation-content :deep(li) {
  margin-bottom: 4px;
}

.explanation-content :deep(strong) {
  font-weight: 600;
}

.explanation-content :deep(code) {
  background-color: rgba(0, 0, 0, 0.06);
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 0.88em;
}

/* Detection Ratio Badge (Part B) */
.detection-ratio-section {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  background-color: var(--bg-page);
  border-radius: 8px;
  border: 1px solid var(--border-light);
}

.detection-badge {
  display: flex;
  align-items: baseline;
  gap: 2px;
  padding: 6px 14px;
  border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.detection-count {
  font-size: 1.5rem;
  font-weight: 700;
  line-height: 1;
}

.detection-sep {
  font-size: 1.1rem;
  font-weight: 500;
  opacity: 0.6;
}

.detection-total {
  font-size: 1.1rem;
  font-weight: 500;
  opacity: 0.7;
}

.detection-label {
  font-size: 0.92rem;
  color: var(--text-muted);
  font-weight: 500;
}

.detection-danger {
  background-color: var(--verdict-phish-bg);
  color: var(--verdict-phish);
  border: 1px solid var(--verdict-phish);
}

.detection-warn {
  background-color: #FFFBEB;
  color: var(--verdict-suspicious);
  border: 1px solid var(--verdict-suspicious);
}

.detection-clean {
  background-color: var(--verdict-safe-bg);
  color: var(--verdict-safe);
  border: 1px solid var(--verdict-safe);
}

.abbr-help {
  font-size: 0.8rem;
  color: var(--accent);
  cursor: help;
  margin-left: 4px;
}

:deep(abbr) {
  text-decoration: underline dotted;
  cursor: help;
}

.technical-card {
  box-shadow: none;
  background: transparent;
  border: none;
  padding: 0;
  gap: 16px;
}

@media (max-width: 640px) {
  .score-container {
    align-items: flex-start;
  }
}
</style>
