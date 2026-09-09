<template>
  <div class="batch-container">
    <!-- Header -->
    <div class="batch-header">
      <div class="badge-tag">
        <Layers :size="14" />
        <span>Incident Triage Mode</span>
      </div>
      <h1 class="batch-title">Batch Email Campaign Clustering</h1>
      <p class="batch-desc">
        Upload multiple <code>.eml</code> complaint files simultaneously. TraceMail AI correlates shared IPs, domains, UPI IDs, crypto wallets, and attachments across the entire batch to expose multi-target attack campaigns.
      </p>
    </div>

    <!-- Upload Area -->
    <div class="card upload-card">
      <div 
        class="dropzone"
        :class="{ 'dropzone-active': isDragging }"
        @dragover.prevent="isDragging = true"
        @dragleave.prevent="isDragging = false"
        @drop.prevent="handleDrop"
        @click="triggerFileInput"
      >
        <input 
          ref="fileInput" 
          type="file" 
          multiple 
          accept=".eml,message/rfc822" 
          class="hidden-input" 
          @change="handleFileSelect" 
        />
        <div class="dropzone-icon">
          <UploadCloud :size="40" />
        </div>
        <div class="dropzone-text">
          <h3>Drop multiple .eml files here, or <span class="browse-link">browse</span></h3>
          <p>Analyze up to 20 raw email complaint files in a single batch</p>
        </div>
      </div>

      <!-- Demo Batch Quick-Load -->
      <div class="demo-batch-row">
        <span class="demo-batch-hint">Judging or testing?</span>
        <button type="button" class="btn-secondary demo-batch-btn" @click.stop="loadDemoBatch">
          <Sparkles :size="15" />
          <span>Load Demo Complaint Batch (3 Emails: 2 Linked Phishing + 1 Safe)</span>
        </button>
      </div>

      <!-- Selected Files Preview -->
      <div v-if="selectedFiles.length > 0" class="selected-files-section">
        <div class="section-title-row">
          <h4>Selected Complaints ({{ selectedFiles.length }})</h4>
          <button class="btn-text" @click="clearFiles">Clear All</button>
        </div>
        <div class="files-grid">
          <div v-for="(file, idx) in selectedFiles" :key="idx" class="file-chip">
            <Mail :size="14" class="file-icon" />
            <span class="file-name" :title="file.name">{{ file.name }}</span>
            <span class="file-size">({{ formatFileSize(file.size) }})</span>
            <button class="remove-file-btn" title="Remove file" @click.stop="removeFile(idx)">
              <X :size="14" />
            </button>
          </div>
        </div>

        <div class="action-row">
          <button 
            class="btn-primary analyze-btn" 
            :disabled="analyzing || selectedFiles.length === 0"
            @click="runBatchAnalysis"
          >
            <Play :size="16" v-if="!analyzing" />
            <div v-else class="spinner spinner-light"></div>
            <span>{{ analyzing ? 'Analyzing Batch Complaints...' : `Analyze Batch (${selectedFiles.length} Emails)` }}</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="analyzing" class="loading-panel card">
      <div class="spinner spinner-dark spinner-large"></div>
      <h3 class="loading-title">Correlating Complaint Infrastructure...</h3>
      <p class="loading-sub">
        Parsing headers, evaluating ML indicators, checking threat intelligence, and building unified graph...
      </p>
    </div>

    <!-- Error Banner -->
    <div v-if="errorMessage" class="error-banner card">
      <AlertTriangle :size="20" class="error-icon" />
      <div class="error-content">
        <h4>Batch Analysis Failed</h4>
        <p>{{ errorMessage }}</p>
      </div>
    </div>

    <!-- Batch Results Section -->
    <div v-if="batchResult && !analyzing" class="results-container">
      <!-- Payoff Banner: Campaign Clusters Detected -->
      <div class="cluster-headline card" :class="batchResult.cluster_count > 0 ? 'cluster-alert' : 'cluster-neutral'">
        <div class="headline-icon-box">
          <Share2 v-if="batchResult.cluster_count > 0" :size="28" />
          <CheckCircle v-else :size="28" />
        </div>
        <div class="headline-text">
          <h2 class="headline-title">
            {{ batchResult.results.length }} complaint{{ batchResult.results.length === 1 ? '' : 's' }} analyzed → 
            <span class="highlight-count">{{ batchResult.cluster_count }}</span> cluster{{ batchResult.cluster_count === 1 ? '' : 's' }} detected
          </h2>
          <p class="headline-sub">
            <span v-if="batchResult.cluster_count > 0">
              Cross-correlated threat infrastructure identified <strong>{{ batchResult.cluster_count }} coordinated campaign{{ batchResult.cluster_count === 1 ? '' : 's' }}</strong> sharing common domains, IPs, UPI handles, or wallets.
            </span>
            <span v-else>
              No multi-email infrastructure overlap detected across this batch. Each analyzed email appears isolated.
            </span>
          </p>
        </div>
      </div>

      <!-- Batch Email Summary Cards Grid -->
      <div class="complaints-grid-section">
        <h3 class="section-heading">Analyzed Email Complaints ({{ batchResult.results.length }})</h3>
        <div class="complaints-grid">
          <div 
            v-for="(res, idx) in batchResult.results" 
            :key="idx" 
            class="complaint-card card"
            :class="getVerdictCardClass(res.verdict)"
          >
            <div class="card-top-row">
              <span class="badge" :class="getVerdictBadgeClass(res.verdict)">
                {{ res.verdict }}
              </span>
              <span class="score-pill" :style="{ color: getVerdictColor(res.verdict) }">
                Risk: <strong>{{ res.risk_score }}</strong>/100
              </span>
            </div>

            <h4 class="complaint-subject" :title="res.subject">
              {{ res.subject || '(No subject provided)' }}
            </h4>

            <div class="complaint-meta">
              <p><strong>From:</strong> <span :title="res.sender">{{ res.sender || 'Unknown' }}</span></p>
              <p v-if="res.filename" class="file-source"><strong>File:</strong> {{ res.filename }}</p>
            </div>

            <!-- Fingerprint Badges if present -->
            <div v-if="hasAnyFingerprints(res)" class="complaint-fp-tags">
              <span v-if="res.upi_ids?.length" class="mini-tag tag-upi">
                UPI: {{ res.upi_ids[0] }}
              </span>
              <span v-if="res.wallet_addresses?.length" class="mini-tag tag-wallet">
                Wallet: {{ res.wallet_addresses[0].slice(0, 8) }}...
              </span>
              <span v-if="res.campaign?.campaign_size > 0" class="mini-tag tag-campaign">
                Linked to {{ res.campaign.campaign_size }} other(s)
              </span>
            </div>

            <div class="card-bottom-action">
              <button class="view-btn" @click="viewSingleResult(res)">
                <span>View Full Forensic Report</span>
                <ArrowRight :size="14" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Per-File Errors (if any) -->
      <div v-if="batchResult.errors && batchResult.errors.length > 0" class="batch-errors-section card">
        <h4 class="error-section-title">
          <AlertTriangle :size="16" />
          <span>Failed to Process {{ batchResult.errors.length }} File{{ batchResult.errors.length === 1 ? '' : 's' }}</span>
        </h4>
        <ul class="error-file-list">
          <li v-for="(err, idx) in batchResult.errors" :key="idx">
            <strong>{{ err.filename }}:</strong> {{ err.error }}
          </li>
        </ul>
      </div>

      <!-- Combined Campaign Graph Component -->
      <div class="combined-graph-section">
        <NetworkGraphPanel 
          :graph-data="batchResult.combined_graph" 
          title="Cross-Complaint Campaign Correlation Graph"
          :hide-notice="true"
        />
      </div>

      <!-- Attachment Intelligence Panel (Phase 17 Part D) -->
      <div v-if="batchEmailHashes.length > 0" class="batch-attachment-section">
        <AttachmentIntelligencePanel :email-hashes="batchEmailHashes" />
      </div>

      <!-- Batch Chat Assistant (Part C) -->
      <div class="batch-chat-section">
        <ChatPanel :context="batchChatContext" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { 
  Layers, 
  UploadCloud, 
  Mail, 
  X, 
  Play, 
  Share2, 
  CheckCircle, 
  AlertTriangle, 
  ArrowRight,
  Sparkles,
} from 'lucide-vue-next'
import { analyzeBatch } from '../api/client'
import { useAnalysisStore } from '../stores/analysis'
import NetworkGraphPanel from '../components/NetworkGraphPanel.vue'
import AttachmentIntelligencePanel from '../components/AttachmentIntelligencePanel.vue'
import ChatPanel from '../components/ChatPanel.vue'

const router = useRouter()
const store = useAnalysisStore()

const fileInput = ref(null)
const selectedFiles = ref([])
const isDragging = ref(false)
const analyzing = ref(false)
const errorMessage = ref(null)

const batchResult = computed({
  get: () => store.currentBatchResult,
  set: (val) => store.setBatchResult(val),
})

const batchEmailHashes = computed(() => {
  return (batchResult.value?.results || []).map(r => r.email_hash).filter(Boolean)
})

function triggerFileInput() {
  if (fileInput.value) {
    fileInput.value.click()
  }
}

function handleFileSelect(e) {
  const files = Array.from(e.target.files || [])
  addFiles(files)
  if (fileInput.value) fileInput.value.value = ''
}

function handleDrop(e) {
  isDragging.value = false
  const files = Array.from(e.dataTransfer.files || [])
  addFiles(files)
}

function addFiles(files) {
  for (const f of files) {
    // Only add if not already in list
    if (!selectedFiles.value.some(existing => existing.name === f.name && existing.size === f.size)) {
      selectedFiles.value.push(f)
    }
  }
}

function loadDemoBatch() {
  const sharedPdfPayload = 'JVBERi0xLjQKJcfsj6IKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIKPj4KZW5kb2JqCg=='

  const sample1 = `Received: from relay2.targetmail.com (relay2.targetmail.com [10.0.0.15])
        by mx.targetmail.com with ESMTP id z991823;
        Mon, 31 Aug 2026 01:10:05 +0000
Received: from mail.attacker-infra.org (mail.attacker-infra.org [185.220.101.5])
        by relay2.targetmail.com with ESMTP id y88123;
        Mon, 31 Aug 2026 01:09:40 +0000
Authentication-Results: mx.targetmail.com;
       spf=softfail (targetmail.com: domain of spoof@compromised-vps.net does not designate 185.220.101.5 as permitted sender);
       dkim=fail header.i=@security-paypa1.com;
       dmarc=fail (p=REJECT) header.from=security-paypa1.com
From: "PayPal Security Alert" <service@security-paypa1.com>
To: "Target Victim" <victim@targetmail.com>
Subject: URGENT: Unauthorized login detected on your account!
Date: Mon, 31 Aug 2026 01:09:30 +0000
Message-ID: <attack.99281.2026@attacker-infra.org>
Reply-To: "Scammer Direct" <dropbox123@gmail.com>
Return-Path: <spoof@compromised-vps.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_DEMO_1===="

--====BOUNDARY_DEMO_1====
Content-Type: text/plain; charset="utf-8"

Dear PayPal Customer,
We detected an unauthorized login attempt from an unknown device.
Please immediately verify your identity by clicking below:
https://paypa1-security-verify.com/login?token=abc891723

Failure to do so will result in permanent suspension.

--====BOUNDARY_DEMO_1====
Content-Type: application/pdf; name="security_patch_update.pdf"
Content-Disposition: attachment; filename="security_patch_update.pdf"
Content-Transfer-Encoding: base64

${sharedPdfPayload}
--====BOUNDARY_DEMO_1====--
`

  const sample2 = `Received: from relay3.victimmail.com (relay3.victimmail.com [10.0.0.20])
        by mx.victimmail.com with ESMTP id a112345;
        Mon, 31 Aug 2026 03:22:15 +0000
Received: from mail.attacker-infra.org (mail.attacker-infra.org [185.220.101.5])
        by relay3.victimmail.com with ESMTP id b223456;
        Mon, 31 Aug 2026 03:21:50 +0000
Authentication-Results: mx.victimmail.com;
       spf=fail (victimmail.com: domain of noreply@fake-paypal-support.com does not designate 185.220.101.5 as permitted sender);
       dkim=fail header.i=@fake-paypal-support.com;
       dmarc=fail (p=REJECT) header.from=fake-paypal-support.com
From: "PayPal Alerts" <noreply@fake-paypal-support.com>
To: "Another Victim" <victim2@victimmail.com>
Subject: Action Required: Verify your PayPal identity now!
Date: Mon, 31 Aug 2026 03:21:30 +0000
Message-ID: <campaign.55512.2026@attacker-infra.org>
Reply-To: "Support Desk" <phish-collect@gmail.com>
Return-Path: <bounce@attacker-infra.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_DEMO_2===="

--====BOUNDARY_DEMO_2====
Content-Type: text/plain; charset="utf-8"

Dear PayPal user,

Your account has been limited due to suspicious activity. Please verify your
identity immediately by visiting:

https://paypa1-security-verify.com/verify?ref=user2-campaign55512

If you do not verify within 24 hours, your account will be permanently closed.

Regards,
PayPal Security Team

--====BOUNDARY_DEMO_2====
Content-Type: application/pdf; name="paypal_identity_form.pdf"
Content-Disposition: attachment; filename="paypal_identity_form.pdf"
Content-Transfer-Encoding: base64

${sharedPdfPayload}
--====BOUNDARY_DEMO_2====--
`

  const sample3 = `Received: from mail-pj1-f41.acme-corp.com (mail-pj1-f41.acme-corp.com [209.85.216.41])
        by mx.google.com with ESMTPS id g19si1092882pll.12.2026.08.31.04.15.30
        for <user@example.com>;
        Mon, 31 Aug 2026 04:15:30 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acme-corp.com;
       spf=pass smtp.mailfrom=bounce@acme-corp.com;
       dmarc=pass header.from=acme-corp.com
From: "Support Team" <support@acme-corp.com>
To: "Valued Customer" <user@example.com>
Subject: Your Monthly Acme Statement
Date: Mon, 31 Aug 2026 04:15:20 -0700
Message-ID: <20260831041520.12345.support@acme-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Customer,

Your statement for August 2026 is ready. Please view it at:
https://portal.acme-corp.com/statements/2026-08

If you have questions, visit https://help.acme-corp.com/faq.

Thanks,
Acme Support Team
`

  const f1 = new File([sample1], 'complaint_phish_1.eml', { type: 'message/rfc822' })
  const f2 = new File([sample2], 'complaint_phish_2.eml', { type: 'message/rfc822' })
  const f3 = new File([sample3], 'complaint_benign_3.eml', { type: 'message/rfc822' })

  selectedFiles.value = [f1, f2, f3]
  batchResult.value = null
  errorMessage.value = null
}

function removeFile(index) {
  selectedFiles.value.splice(index, 1)
}

function clearFiles() {
  selectedFiles.value = []
  batchResult.value = null
  errorMessage.value = null
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

async function runBatchAnalysis() {
  if (selectedFiles.value.length === 0) return

  analyzing.value = true
  errorMessage.value = null
  batchResult.value = null

  try {
    const formData = new FormData()
    for (const file of selectedFiles.value) {
      formData.append('files', file)
    }

    const res = await analyzeBatch(formData)
    batchResult.value = res
  } catch (err) {
    console.error('Batch analysis failed', err)
    errorMessage.value = err.response?.data?.detail || 'Failed to complete batch analysis. Please try again.'
  } finally {
    analyzing.value = false
  }
}

function viewSingleResult(result) {
  store.setAnalysis(result)
  router.push({ path: '/results', query: { fromBatch: 'true' } })
}

const batchChatContext = computed(() => {
  const b = batchResult.value
  if (!b) return null
  const verdicts = {}
  for (const r of (b.results || [])) {
    verdicts[r.verdict] = (verdicts[r.verdict] || 0) + 1
  }
  return {
    batch_size: b.results?.length || 0,
    cluster_count: b.cluster_count || 0,
    verdicts: verdicts,
  }
})

function hasAnyFingerprints(res) {
  return Boolean(
    res.upi_ids?.length || 
    res.wallet_addresses?.length || 
    res.campaign?.campaign_size > 0
  )
}

function getVerdictCardClass(verdict) {
  if (verdict === 'Safe') return 'border-safe'
  if (verdict === 'Suspicious') return 'border-suspicious'
  return 'border-phish'
}

function getVerdictBadgeClass(verdict) {
  if (verdict === 'Safe') return 'badge-safe'
  if (verdict === 'Suspicious') return 'badge-suspicious'
  return 'badge-phish'
}

function getVerdictColor(verdict) {
  if (verdict === 'Safe') return 'var(--verdict-safe)'
  if (verdict === 'Suspicious') return 'var(--verdict-suspicious)'
  return 'var(--verdict-phish)'
}
</script>

<style scoped>
.batch-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 36px 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.batch-header {
  margin-bottom: 4px;
}

.badge-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background-color: var(--accent-light);
  color: var(--accent);
  padding: 4px 10px;
  border-radius: 9999px;
  font-size: 0.8rem;
  font-weight: 600;
  margin-bottom: 12px;
}

.batch-title {
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--text-main);
  margin-bottom: 8px;
}

.batch-desc {
  font-size: 1.05rem;
  color: var(--text-muted);
  max-width: 800px;
  line-height: 1.5;
}

.batch-desc code {
  background-color: var(--bg-page);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.95em;
  border: 1px solid var(--border-light);
}

.upload-card {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.dropzone {
  border: 2px dashed var(--border-focus);
  border-radius: 8px;
  padding: 36px 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  cursor: pointer;
  background-color: var(--bg-page);
  transition: all 0.2s ease;
}

.dropzone:hover, .dropzone-active {
  border-color: var(--accent);
  background-color: var(--accent-light);
}

.dropzone-icon {
  color: var(--accent);
}

.dropzone-text {
  text-align: center;
}

.dropzone-text h3 {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text-main);
  margin-bottom: 4px;
}

.browse-link {
  color: var(--accent);
  text-decoration: underline;
}

.dropzone-text p {
  font-size: 0.88rem;
  color: var(--text-muted);
}

.hidden-input {
  display: none;
}

/* Demo Batch Quick-Load */
.demo-batch-row {
  display: flex;
  align-items: center;
  gap: 10px;
  background-color: var(--bg-page);
  padding: 10px 14px;
  border-radius: 6px;
  border: 1px dashed var(--border-light);
}

.demo-batch-hint {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-muted);
}

.demo-batch-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  font-size: 0.84rem;
  color: var(--accent);
  border-color: var(--accent-light);
}

.demo-batch-btn:hover {
  background-color: var(--accent-light);
}

/* Selected Files Section */
.selected-files-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
  border-top: 1px solid var(--border-light);
  padding-top: 16px;
}

.section-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-title-row h4 {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-main);
}

.btn-text {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 0.85rem;
  cursor: pointer;
  padding: 4px 8px;
}

.btn-text:hover {
  color: var(--verdict-phish);
}

.files-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  max-height: 180px;
  overflow-y: auto;
  padding-right: 4px;
}

.file-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 0.85rem;
}

.file-icon {
  color: var(--accent);
  flex-shrink: 0;
}

.file-name {
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-main);
  font-weight: 500;
}

.file-size {
  color: var(--text-muted);
  font-size: 0.78rem;
}

.remove-file-btn {
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  padding: 0;
  margin-left: 2px;
}

.remove-file-btn:hover {
  color: var(--verdict-phish);
}

.action-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 6px;
}

.analyze-btn {
  padding: 10px 24px;
  font-size: 0.95rem;
}

/* Loading & Error States */
.loading-panel {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  gap: 12px;
  text-align: center;
}

.spinner-large {
  width: 32px;
  height: 32px;
  border-width: 3px;
}

.loading-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-main);
}

.loading-sub {
  font-size: 0.95rem;
  color: var(--text-muted);
  max-width: 500px;
}

.error-banner {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  background-color: var(--verdict-phish-bg);
  border-left: 4px solid var(--verdict-phish);
}

.error-icon {
  color: var(--verdict-phish);
  flex-shrink: 0;
  margin-top: 2px;
}

.error-content h4 {
  color: var(--verdict-phish);
  margin-bottom: 4px;
}

.error-content p {
  color: var(--text-main);
  font-size: 0.9rem;
}

/* Results & Clusters */
.results-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.cluster-headline {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 24px 28px;
  border-radius: 12px;
}

.cluster-alert {
  background: linear-gradient(135deg, #FEF2F2 0%, #FFFBEB 100%);
  border: 1px solid #FECDD3;
}

.cluster-alert .headline-icon-box {
  background-color: #FEE2E2;
  color: #DC2626;
}

.cluster-alert .highlight-count {
  color: #DC2626;
}

.cluster-neutral {
  background: linear-gradient(135deg, #F0FDF4 0%, #EFF6FF 100%);
  border: 1px solid #BBF7D0;
}

.cluster-neutral .headline-icon-box {
  background-color: #DCFCE7;
  color: #16A34A;
}

.cluster-neutral .highlight-count {
  color: #16A34A;
}

.headline-icon-box {
  width: 54px;
  height: 54px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.headline-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text-main);
  margin-bottom: 4px;
}

.headline-sub {
  font-size: 0.98rem;
  color: var(--text-muted);
  line-height: 1.4;
}

/* Complaints Grid */
.complaints-grid-section {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.section-heading {
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--text-main);
}

.complaints-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}

.complaint-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px 18px;
  border-radius: 8px;
  border-left-width: 4px;
  border-left-style: solid;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.complaint-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
}

.border-safe { border-left-color: var(--verdict-safe); }
.border-suspicious { border-left-color: var(--verdict-suspicious); }
.border-phish { border-left-color: var(--verdict-phish); }

.card-top-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.score-pill {
  font-size: 0.85rem;
  font-weight: 500;
}

.complaint-subject {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-main);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.complaint-meta {
  font-size: 0.85rem;
  color: var(--text-muted);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.complaint-meta p {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.file-source {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 0.8rem;
}

.complaint-fp-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 2px;
}

.mini-tag {
  font-size: 0.75rem;
  padding: 2px 6px;
  border-radius: 4px;
  font-weight: 500;
}

.tag-upi {
  background-color: #F5F3FF;
  color: #7C3AED;
  border: 1px solid #DDD6FE;
}

.tag-wallet {
  background-color: #FFFBEB;
  color: #D97706;
  border: 1px solid #FDE68A;
}

.tag-campaign {
  background-color: #FEF2F2;
  color: #DC2626;
  border: 1px solid #FECDD3;
}

.card-bottom-action {
  border-top: 1px solid var(--border-light);
  padding-top: 10px;
  margin-top: auto;
}

.view-btn {
  background: none;
  border: none;
  color: var(--accent);
  font-size: 0.85rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  padding: 0;
}

.view-btn:hover {
  text-decoration: underline;
}

.batch-errors-section {
  background-color: var(--bg-page);
}

.error-section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--verdict-phish);
  font-size: 0.95rem;
  margin-bottom: 8px;
}

.error-file-list {
  padding-left: 20px;
  font-size: 0.85rem;
  color: var(--text-main);
}

.error-file-list li {
  margin-bottom: 4px;
}

.combined-graph-section {
  margin-top: 8px;
}

.batch-attachment-section {
  margin-top: 16px;
}
</style>
