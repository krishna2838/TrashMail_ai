<template>
  <div :class="['card', 'hop-card', { 'details-only-card': onlyDetails }]">
    <div class="card-header">
      <div class="title-with-icon">
        <Server :size="20" class="header-icon" />
        <h2>{{ onlyDetails ? 'Full MTA Hop Trace' : 'Email Relay Hop Timeline' }}</h2>
      </div>
      <span class="badge badge-subtle">{{ hops.length }} {{ hops.length === 1 ? 'Hop' : 'Hops' }}</span>
    </div>
    <p v-if="!hideDetails" class="section-desc">
      Chronological sequence of <abbr title="Mail Transfer Agent: a server that receives and forwards email across the internet">mail transfer agents (MTAs)</abbr> that routed this message, from origin to recipient inbox.
    </p>

    <!-- Part C — Plain-language summary (Hidden in onlyDetails mode) -->
    <div v-if="!onlyDetails && hops && hops.length > 0" class="hop-summary-banner">
      <span class="hop-summary-text">
        This email passed through <strong>{{ hops.length }}</strong> 
        <abbr title="Mail Transfer Agent (MTA): an intermediate server that forwards email across the internet">mail {{ hops.length === 1 ? 'server' : 'servers' }}</abbr>
        before reaching the inbox<template v-if="originCountry">, originating from a server in <strong>{{ originCountry }}</strong></template>.
      </span>
    </div>

    <!-- Detailed Hop Timeline (Technical: hidden when hideDetails is true) -->
    <div v-if="!hideDetails && hops && hops.length > 0" class="timeline">
      <div 
        v-for="(hop, idx) in sortedHops" 
        :key="hop.sequence || idx" 
        :class="['timeline-item', { 'is-origin': isOriginHop(hop), 'is-internal': !hop.is_public_ip }]"
      >
        <div class="timeline-marker-col">
          <div :class="['marker-dot', { 'dot-origin': isOriginHop(hop), 'dot-internal': !hop.is_public_ip }]">
            <span class="marker-seq">{{ hop.sequence || idx + 1 }}</span>
          </div>
          <div v-if="idx < sortedHops.length - 1" class="marker-line"></div>
        </div>

        <div class="timeline-content">
          <div class="hop-header-row">
            <span class="hop-role">
              {{ isOriginHop(hop) ? 'Originating Mail Server (Sender)' : `Hop #${hop.sequence || idx + 1}` }}
            </span>
            <span v-if="isOriginHop(hop)" class="origin-badge">
              Originating IP
            </span>
            <span v-else-if="!hop.is_public_ip" class="internal-badge">
              Internal Relay
            </span>
          </div>

          <div class="hop-details">
            <div v-if="hop.from_ip || hop.from_host" class="hop-field">
              <span class="field-label">From:</span>
              <span class="field-value mono">
                {{ hop.from_host || 'N/A' }} 
                <span v-if="hop.from_ip" class="ip-tag">[{{ hop.from_ip }}]</span>
              </span>
            </div>
            <div v-if="hop.by_host" class="hop-field">
              <span class="field-label">Received By:</span>
              <span class="field-value mono">{{ hop.by_host }}</span>
            </div>
            <div v-if="hop.timestamp" class="hop-field">
              <span class="field-label">Timestamp:</span>
              <span class="field-value time-val">{{ formatTimestamp(hop.timestamp) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else-if="!hideDetails" class="empty-state">
      <p>No Received header hops found in this email.</p>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Server } from 'lucide-vue-next'

const props = defineProps({
  hops: {
    type: Array,
    default: () => [],
  },
  originatingIp: {
    type: String,
    default: '',
  },
  originGeo: {
    type: Object,
    default: null,
  },
  hideDetails: {
    type: Boolean,
    default: false,
  },
  onlyDetails: {
    type: Boolean,
    default: false,
  },
})

// Extract country for plain-language summary
const originCountry = computed(() => {
  if (!props.originGeo || typeof props.originGeo !== 'object') return ''
  return props.originGeo.country || ''
})

// Sort hops chronologically: sequence 1 first
const sortedHops = computed(() => {
  return [...props.hops].sort((a, b) => (a.sequence || 0) - (b.sequence || 0))
})

function isOriginHop(hop) {
  if (!props.originatingIp) return false
  return hop.from_ip === props.originatingIp
}

function formatTimestamp(ts) {
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts
    return d.toUTCString()
  } catch {
    return ts
  }
}
</script>

<style scoped>
.hop-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.title-with-icon {
  display: flex;
  align-items: center;
  gap: 10px;
}

.header-icon {
  color: var(--accent);
}

.badge-subtle {
  background-color: var(--bg-page);
  color: var(--text-muted);
  font-size: 0.8rem;
  padding: 3px 10px;
  border-radius: 9999px;
  border: 1px solid var(--border-light);
}

.section-desc {
  font-size: 0.9rem;
  color: var(--text-muted);
  line-height: 1.5;
}

.timeline {
  display: flex;
  flex-direction: column;
  margin-top: 8px;
}

.timeline-item {
  display: flex;
  gap: 16px;
  position: relative;
}

.timeline-marker-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 28px;
  flex-shrink: 0;
}

.marker-dot {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background-color: var(--bg-page);
  border: 2px solid var(--border-light);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2;
}

.marker-seq {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-muted);
}

.marker-dot.dot-origin {
  background-color: var(--accent-light);
  border-color: var(--accent);
}

.marker-dot.dot-origin .marker-seq {
  color: var(--accent);
}

.marker-dot.dot-internal {
  opacity: 0.6;
}

.marker-line {
  width: 2px;
  flex: 1;
  background-color: var(--border-light);
  margin: 4px 0;
  min-height: 32px;
}

.timeline-content {
  flex: 1;
  padding-bottom: 20px;
}

.hop-header-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.hop-role {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-main);
}

.origin-badge {
  background-color: var(--accent-light);
  color: var(--accent);
  font-size: 0.75rem;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 4px;
}

.internal-badge {
  background-color: var(--bg-page);
  color: var(--text-light);
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 4px;
}

.timeline-item.is-internal .timeline-content {
  opacity: 0.65;
}

.hop-details {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 0.88rem;
}

.hop-field {
  display: flex;
  gap: 6px;
  align-items: baseline;
  flex-wrap: wrap;
}

.field-label {
  color: var(--text-muted);
  font-size: 0.82rem;
  min-width: 85px;
}

.field-value {
  color: var(--text-main);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.ip-tag {
  color: var(--accent);
  font-weight: 600;
}

.time-val {
  color: var(--text-muted);
  font-size: 0.82rem;
}

.empty-state {
  padding: 24px;
  text-align: center;
  color: var(--text-muted);
}

/* Part C — Hop summary banner */
.hop-summary-banner {
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
  padding: 10px 14px;
}

.hop-summary-text {
  font-size: 0.92rem;
  color: var(--text-main);
  line-height: 1.5;
}

.hop-summary-text strong {
  font-weight: 600;
  color: var(--accent);
}

abbr {
  text-decoration: underline dotted;
  cursor: help;
}

.details-only-card {
  box-shadow: none;
  background: transparent;
  border: none;
  padding: 0;
}
</style>
