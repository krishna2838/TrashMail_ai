<template>
  <div class="analyze-container">
    <div class="card analyze-card">
      <div class="analyze-header">
        <Shield :size="28" class="brand-icon" />
        <h1>Email Forensic Analysis</h1>
        <p class="subtitle">
          Submit a raw email message or upload an <code>.eml</code> file to inspect headers, authenticate routing hops, score phishing probability, and trace infrastructure.
        </p>
      </div>

      <form class="analyze-form" @submit.prevent="handleSubmit">
        <!-- Tab Selector: Text Paste vs File Upload -->
        <div class="input-tabs">
          <button 
            type="button" 
            :class="['tab-btn', activeTab === 'paste' ? 'tab-active' : '']"
            @click="activeTab = 'paste'"
          >
            <FileText :size="16" />
            <span>Paste Raw Email</span>
          </button>
          <button 
            type="button" 
            :class="['tab-btn', activeTab === 'upload' ? 'tab-active' : '']"
            @click="activeTab = 'upload'"
          >
            <Upload :size="16" />
            <span>Upload .eml File</span>
          </button>
        </div>

        <!-- Tab 1: Text Area -->
        <div v-show="activeTab === 'paste'" class="tab-pane">
          <div class="textarea-wrapper">
            <textarea 
              v-model="rawEmailText" 
              placeholder="Paste RFC 822 raw email headers and body here...&#10;&#10;Received: from mail.example.com ...&#10;From: sender@example.com&#10;Subject: Urgent Security Notice&#10;..." 
              rows="12"
              class="raw-textarea"
              :disabled="loading"
            ></textarea>
          </div>
          <div class="quick-samples">
            <span class="samples-label">Try sample:</span>
            <button type="button" class="sample-chip" @click="loadSample('phish')">
              Sample Phishing Email
            </button>
            <button type="button" class="sample-chip" @click="loadSample('benign')">
              Sample Benign Statement
            </button>
          </div>
        </div>

        <!-- Tab 2: Drag and Drop Upload -->
        <div v-show="activeTab === 'upload'" class="tab-pane">
          <div 
            :class="['dropzone', isDragging ? 'dropzone-active' : '', selectedFile ? 'dropzone-has-file' : '']"
            @dragover.prevent="isDragging = true"
            @dragleave.prevent="isDragging = false"
            @drop.prevent="handleFileDrop"
            @click="triggerFileInput"
          >
            <input 
              ref="fileInputRef" 
              type="file" 
              accept=".eml,message/rfc822" 
              class="hidden-file-input"
              @change="handleFileSelect"
            />
            
            <div v-if="!selectedFile" class="dropzone-prompt">
              <UploadCloud :size="40" class="upload-icon" />
              <p class="dropzone-title">Click to upload or drag & drop an .eml file</p>
              <p class="dropzone-sub">RFC 822 format email exports (max 5 MB)</p>
            </div>

            <div v-else class="selected-file-info">
              <FileCheck :size="32" class="file-ready-icon" />
              <div class="file-details">
                <span class="file-name">{{ selectedFile.name }}</span>
                <span class="file-size">{{ (selectedFile.size / 1024).toFixed(1) }} KB</span>
              </div>
              <button type="button" class="remove-file-btn" @click.stop="selectedFile = null">
                &times;
              </button>
            </div>
          </div>
        </div>

        <!-- Error Card -->
        <div v-if="errorMessage" class="error-card">
          <AlertCircle :size="20" class="error-icon" />
          <div class="error-text">
            <p class="error-title">Analysis Failed</p>
            <p class="error-detail">{{ errorMessage }}</p>
          </div>
        </div>

        <!-- Submit Button -->
        <div class="actions-row">
          <button 
            type="submit" 
            class="btn-primary analyze-submit-btn" 
            :disabled="loading || (!rawEmailText.trim() && !selectedFile)"
          >
            <div v-if="loading" class="spinner"></div>
            <Sparkles v-else :size="18" />
            <span>{{ loading ? 'Running Forensic Pipeline...' : 'Analyze Email' }}</span>
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Shield, FileText, Upload, UploadCloud, FileCheck, AlertCircle, Sparkles } from 'lucide-vue-next'
import { useAnalysisStore } from '../stores/analysis'
import { analyzeEmail } from '../api/client'

const router = useRouter()
const store = useAnalysisStore()

const activeTab = ref('paste')
const rawEmailText = ref('')
const selectedFile = ref(null)
const fileInputRef = ref(null)
const isDragging = ref(false)
const loading = ref(false)
const errorMessage = ref(null)

function triggerFileInput() {
  if (fileInputRef.value) {
    fileInputRef.value.click()
  }
}

function handleFileSelect(e) {
  const files = e.target.files
  if (files && files[0]) {
    selectedFile.value = files[0]
  }
}

function handleFileDrop(e) {
  isDragging.value = false
  const files = e.dataTransfer.files
  if (files && files[0]) {
    selectedFile.value = files[0]
  }
}

function loadSample(type) {
  activeTab.value = 'paste'
  if (type === 'phish') {
    rawEmailText.value = `Received: from relay2.targetmail.com (relay2.targetmail.com [10.0.0.15])
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
Content-Type: multipart/mixed; boundary="====PHISH_BOUNDARY_982736===="

--====PHISH_BOUNDARY_982736====
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear PayPal Customer,</p>
<p>We detected an unauthorized login attempt from an unknown device.</p>
<p>Please immediately verify your identity by clicking below:</p>
<p><a href="https://paypa1-security-verify.com/login?token=abc891723">https://paypa1-security-verify.com/login?token=abc891723</a></p>
<p>Failure to do so will result in permanent suspension.</p>
<p>Download and run our urgent security patch tool attached.</p>
</body>
</html>

--====PHISH_BOUNDARY_982736====
Content-Type: application/octet-stream; name="paypal_security_fix.scr"
Content-Disposition: attachment; filename="paypal_security_fix.scr"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--====PHISH_BOUNDARY_982736====--`
  } else {
    rawEmailText.value = `Received: by 2002:a05:6808:1c88:b0:3c8:51e8:5640 with SMTP id abc123def456;
        Mon, 31 Aug 2026 04:15:31 -0700 (PDT)
Received: from mail-pj1-f41.acme-corp.com (mail-pj1-f41.acme-corp.com [209.85.216.41])
        by mx.google.com with ESMTPS id g19si1092882pll.12.2026.08.31.04.15.30
        for <user@example.com>;
        Mon, 31 Aug 2026 04:15:30 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acme-corp.com header.s=20240101;
       spf=pass (google.com: domain of bounce@acme-corp.com designates 209.85.216.41 as permitted sender);
       dmarc=pass (p=REJECT) header.from=acme-corp.com
From: "Support Team" <support@acme-corp.com>
To: "Valued Customer" <user@example.com>
Subject: Your Monthly Acme Statement
Date: Mon, 31 Aug 2026 04:15:20 -0700
Message-ID: <20260831041520.12345.support@acme-corp.com>
Reply-To: "Support Team" <support@acme-corp.com>
Return-Path: <bounce@acme-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Customer,

Your statement for August 2026 is ready. Please view it at:
https://portal.acme-corp.com/statements/2026-08

If you have questions, visit https://help.acme-corp.com/faq.

Thanks,
Acme Support Team`
  }
}

async function handleSubmit() {
  errorMessage.value = null
  loading.value = true

  try {
    let result
    if (activeTab.value === 'upload' && selectedFile.value) {
      const formData = new FormData()
      formData.append('file', selectedFile.value)
      result = await analyzeEmail(formData, true)
    } else if (rawEmailText.value.trim()) {
      result = await analyzeEmail({ raw_email: rawEmailText.value }, false)
    } else {
      errorMessage.value = 'Please paste raw email headers or upload an .eml file.'
      loading.value = false
      return
    }

    // Save in store and navigate to results view
    store.setAnalysis(result)
    router.push('/results')
  } catch (err) {
    console.error('Analysis submission failed', err)
    if (err.response?.status === 413) {
      errorMessage.value = 'Email payload exceeds maximum size limit (5 MB).'
    } else if (err.response?.data?.detail) {
      errorMessage.value = err.response.data.detail
    } else {
      errorMessage.value = 'Failed to analyze email. Ensure the backend server is reachable.'
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.analyze-container {
  display: flex;
  justify-content: center;
  padding: 40px 16px;
}

.analyze-card {
  max-width: 720px;
  width: 100%;
}

.analyze-header {
  text-align: center;
  margin-bottom: 24px;
}

.brand-icon {
  color: var(--accent);
  margin-bottom: 8px;
}

.analyze-header h1 {
  font-size: 1.6rem;
  margin-bottom: 8px;
}

.subtitle {
  font-size: 0.92rem;
  color: var(--text-muted);
  max-width: 580px;
  margin: 0 auto;
}

.subtitle code {
  background-color: var(--bg-page);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.88rem;
  color: var(--accent);
}

.analyze-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.input-tabs {
  display: flex;
  border-bottom: 1px solid var(--border-light);
  gap: 8px;
}

.tab-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  background: none;
  border: none;
  padding: 10px 16px;
  font-family: var(--font-family);
  font-size: 0.92rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: color 0.15s ease, border-color 0.15s ease;
}

.tab-btn:hover {
  color: var(--text-main);
}

.tab-active {
  color: var(--accent);
  border-bottom-color: var(--accent);
}

.tab-pane {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.textarea-wrapper {
  width: 100%;
}

.raw-textarea {
  width: 100%;
  padding: 14px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.85rem;
  line-height: 1.45;
  color: var(--text-main);
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  border-radius: 8px;
  outline: none;
  resize: vertical;
  transition: border-color 0.15s ease;
}

.raw-textarea:focus {
  border-color: var(--border-focus);
  background-color: #FFFFFF;
}

.quick-samples {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 0.85rem;
}

.samples-label {
  color: var(--text-muted);
}

.sample-chip {
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  color: var(--text-main);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.82rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.sample-chip:hover {
  background-color: var(--accent-light);
  border-color: var(--accent);
  color: var(--accent);
}

/* Dropzone */
.dropzone {
  border: 2px dashed var(--border-light);
  border-radius: 8px;
  padding: 40px 20px;
  text-align: center;
  background-color: var(--bg-page);
  cursor: pointer;
  transition: border-color 0.15s ease, background-color 0.15s ease;
}

.dropzone:hover, .dropzone-active {
  border-color: var(--accent);
  background-color: var(--accent-light);
}

.hidden-file-input {
  display: none;
}

.upload-icon {
  color: var(--accent);
  margin-bottom: 12px;
}

.dropzone-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-main);
  margin-bottom: 4px;
}

.dropzone-sub {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.selected-file-info {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

.file-ready-icon {
  color: var(--verdict-safe);
}

.file-details {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}

.file-name {
  font-weight: 600;
  color: var(--text-main);
  font-size: 0.92rem;
}

.file-size {
  font-size: 0.82rem;
  color: var(--text-muted);
}

.remove-file-btn {
  background: none;
  border: none;
  font-size: 1.4rem;
  color: var(--text-muted);
  cursor: pointer;
  margin-left: 8px;
}

.remove-file-btn:hover {
  color: var(--verdict-phish);
}

/* Error Card */
.error-card {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  background-color: var(--verdict-phish-bg);
  border: 1px solid var(--verdict-phish);
  border-radius: 8px;
  padding: 14px 16px;
}

.error-icon {
  color: var(--verdict-phish);
  flex-shrink: 0;
  margin-top: 2px;
}

.error-title {
  font-weight: 600;
  color: var(--verdict-phish);
  font-size: 0.9rem;
}

.error-detail {
  font-size: 0.85rem;
  color: var(--text-main);
  margin-top: 2px;
}

.actions-row {
  display: flex;
  justify-content: flex-end;
}

.analyze-submit-btn {
  padding: 12px 24px;
  font-size: 1rem;
}
</style>
