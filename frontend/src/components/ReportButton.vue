<template>
  <button 
    class="btn-secondary report-btn"
    :disabled="!emailHash"
    @click="downloadReport"
  >
    <FileText :size="18" />
    <span>Download Forensic Report (PDF)</span>
  </button>
</template>

<script setup>
import { FileText } from 'lucide-vue-next'
import { getReportUrl } from '../api/client'

const props = defineProps({
  emailHash: {
    type: String,
    default: '',
  },
})

function downloadReport() {
  if (!props.emailHash) return
  const url = getReportUrl(props.emailHash)
  // Open in new tab / initiate download
  window.open(url, '_blank')
}
</script>

<style scoped>
.report-btn {
  font-size: 0.9rem;
  font-weight: 500;
  padding: 8px 16px;
}
</style>
