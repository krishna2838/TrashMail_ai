<template>
  <div v-if="loaded && data.total_attachments > 0" class="attachment-intel-card">
    <button
      type="button"
      class="attachment-toggle-btn"
      @click="isExpanded = !isExpanded"
    >
      <div class="toggle-left">
        <Paperclip :size="16" class="toggle-icon" />
        <h3 class="section-subtitle">Attachment Intelligence</h3>
        <span v-if="loaded && !error" class="count-badges">
          <span class="count-badge">{{ data.total_attachments }} found</span>
          <span class="count-badge">{{ data.total_unique_attachments }} unique</span>
          <span v-if="data.total_reused > 0" class="count-badge count-reused">{{ data.total_reused }} reused</span>
        </span>
      </div>
      <ChevronUp v-if="isExpanded" :size="16" class="toggle-chevron" />
      <ChevronDown v-else :size="16" class="toggle-chevron" />
    </button>

    <div v-if="isExpanded" class="attachment-body">
      <!-- Loading -->
      <div v-if="loading" class="attachment-loading">
        <div class="spinner spinner-dark"></div>
        <span>Querying attachment reuse data…</span>
      </div>

      <!-- Error -->
      <div v-else-if="error" class="attachment-error">
        <span>{{ error }}</span>
      </div>

      <!-- Loaded but no reused attachments -->
      <div v-else-if="data.total_reused === 0" class="attachment-empty">
        <CheckCircle :size="16" />
        <span>No attachments were reused across multiple emails in this set.</span>
      </div>

      <!-- Reused attachments table -->
      <div v-else class="reused-list">
        <div class="reused-heading">
          <AlertTriangle :size="16" class="reused-icon" />
          <span><strong>{{ data.total_reused }}</strong> attachment{{ data.total_reused === 1 ? '' : 's' }} found in multiple emails — possible file reuse / phishing kit indicators.</span>
        </div>
        <div v-for="(att, idx) in data.reused_attachments" :key="idx" class="reused-entry">
          <div class="reused-hash-row">
            <span class="hash-label">SHA-256</span>
            <code class="hash-value">{{ att.hash }}</code>
            <span class="seen-count">seen in {{ att.seen_in_count }} emails</span>
          </div>

          <!-- Filenames — the forensic point -->
          <div v-if="att.filenames && att.filenames.length > 0" class="filenames-row">
            <span class="filenames-label">{{ att.filenames.length === 1 ? 'Filename:' : 'Disguised as:' }}</span>
            <span v-for="(fn, j) in att.filenames" :key="j" class="filename-pill">{{ fn }}</span>
          </div>

          <!-- Which emails -->
          <div class="reused-emails">
            <div v-for="(em, j) in att.emails" :key="j" class="reused-email-row">
              <span :class="['mini-badge', getBadgeClass(em.verdict)]">{{ em.verdict }}</span>
              <span class="reused-email-subject">{{ em.subject || '(No subject)' }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import { Paperclip, ChevronUp, ChevronDown, CheckCircle, AlertTriangle } from 'lucide-vue-next'
import { getAttachmentIntelligence } from '../api/client'

const props = defineProps({
  emailHashes: {
    type: Array,
    default: () => [],
  },
})

const isExpanded = ref(false)
const loading = ref(false)
const loaded = ref(false)
const error = ref(null)
const data = ref({
  reused_attachments: [],
  total_attachments: 0,
  total_unique_attachments: 0,
  total_reused: 0,
})

function getBadgeClass(verdict) {
  if (verdict === 'Safe') return 'badge-safe'
  if (verdict === 'Suspicious') return 'badge-suspicious'
  return 'badge-phish'
}

async function fetchData() {
  if (!props.emailHashes || props.emailHashes.length === 0) return
  loading.value = true
  error.value = null
  try {
    const result = await getAttachmentIntelligence(props.emailHashes)
    data.value = result
    loaded.value = true
  } catch (err) {
    console.error('Failed to load attachment intelligence', err)
    error.value = 'Could not load attachment intelligence from server.'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchData()
})

watch(() => props.emailHashes, () => {
  fetchData()
}, { deep: true })
</script>

<style scoped>
.attachment-intel-card {
  border: 1px solid var(--border-light);
  border-radius: 8px;
  overflow: hidden;
}

.attachment-toggle-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 10px 14px;
  background-color: var(--bg-page, #F8F9FB);
  border: none;
  cursor: pointer;
  font-family: inherit;
  text-align: left;
  transition: background-color 0.15s ease;
}

.attachment-toggle-btn:hover {
  background-color: var(--accent-light, #EFF6FF);
}

.toggle-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.toggle-icon {
  color: var(--accent, #1D4ED8);
  flex-shrink: 0;
}

.section-subtitle {
  font-size: 0.9rem;
  font-weight: 600;
  margin: 0;
  color: var(--text-main, #111827);
}

.count-badges {
  display: flex;
  gap: 4px;
}

.count-badge {
  display: inline-block;
  background-color: #F3F4F6;
  color: #6B7280;
  border: 1px solid #E5E7EB;
  border-radius: 9999px;
  padding: 1px 8px;
  font-size: 0.72rem;
  font-weight: 500;
  white-space: nowrap;
}

.count-reused {
  background-color: #FEF2F2;
  color: #B91C1C;
  border-color: #FECACA;
}

.toggle-chevron {
  color: var(--text-muted, #6B7280);
  flex-shrink: 0;
}

.attachment-body {
  padding: 14px;
  border-top: 1px solid var(--border-light, #E5E7EB);
}

.attachment-loading {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--text-muted, #6B7280);
  font-size: 0.9rem;
  padding: 12px 0;
}

.attachment-error {
  color: var(--verdict-phish, #B91C1C);
  font-size: 0.9rem;
  padding: 8px 0;
}

.attachment-empty {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted, #6B7280);
  font-size: 0.9rem;
}

.attachment-empty svg {
  color: var(--verdict-safe, #15803D);
}

.reused-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.reused-heading {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 0.88rem;
  color: var(--text-main);
  background-color: #FEF2F2;
  border-left: 3px solid #EF4444;
  border-radius: 6px;
  padding: 8px 12px;
}

.reused-icon {
  color: #EF4444;
  flex-shrink: 0;
  margin-top: 2px;
}

.reused-entry {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid var(--border-light, #E5E7EB);
  border-radius: 8px;
  background-color: #FFFFFF;
}

.reused-hash-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.hash-label {
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.hash-value {
  font-size: 0.78rem;
  background-color: rgba(0, 0, 0, 0.05);
  padding: 2px 6px;
  border-radius: 4px;
  word-break: break-all;
  flex: 1;
  min-width: 0;
}

.seen-count {
  font-size: 0.78rem;
  color: #B91C1C;
  font-weight: 600;
  white-space: nowrap;
}

.filenames-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.filenames-label {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-main);
}

.filename-pill {
  display: inline-block;
  background-color: #FFFBEB;
  color: #92400E;
  border: 1px solid #F59E0B;
  border-radius: 4px;
  padding: 1px 7px;
  font-size: 0.78rem;
  font-weight: 500;
  font-family: 'SF Mono', 'Cascadia Code', monospace;
}

.reused-emails {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding-left: 4px;
}

.reused-email-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.84rem;
}

.mini-badge {
  font-size: 0.68rem;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 600;
  white-space: nowrap;
}

.reused-email-subject {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-main);
}
</style>
