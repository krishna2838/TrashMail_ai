import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useAnalysisStore = defineStore('analysis', () => {
  const currentAnalysis = ref(null)
  const loading = ref(false)
  const error = ref(null)

  // Local storage backed history for Phase 6
  const savedHistory = localStorage.getItem('trashmail_history')
  const history = ref(savedHistory ? JSON.parse(savedHistory) : [])

  const hasAnalysis = computed(() => !!currentAnalysis.value)

  const verdictClass = computed(() => {
    if (!currentAnalysis.value) return ''
    const v = currentAnalysis.value.verdict
    if (v === 'Safe') return 'badge-safe'
    if (v === 'Suspicious') return 'badge-suspicious'
    return 'badge-phish'
  })

  const verdictColor = computed(() => {
    if (!currentAnalysis.value) return '#6B7280'
    const v = currentAnalysis.value.verdict
    if (v === 'Safe') return 'var(--verdict-safe)'
    if (v === 'Suspicious') return 'var(--verdict-suspicious)'
    return 'var(--verdict-phish)'
  })

  function setAnalysis(data) {
    currentAnalysis.value = data
    error.value = null

    // Add to history if not already present
    if (data && data.email_hash) {
      const existingIdx = history.value.findIndex(item => item.email_hash === data.email_hash)
      const entry = {
        email_hash: data.email_hash,
        subject: data.subject || '(No Subject)',
        sender: data.sender || 'Unknown Sender',
        verdict: data.verdict,
        risk_score: data.risk_score,
        analyzed_at: new Date().toISOString(),
      }

      if (existingIdx !== -1) {
        history.value[existingIdx] = entry
      } else {
        history.value.unshift(entry)
      }

      // Limit history to 20 items
      if (history.value.length > 20) {
        history.value = history.value.slice(0, 20)
      }

      try {
        localStorage.setItem('trashmail_history', JSON.stringify(history.value))
      } catch (e) {
        console.warn('Could not persist history to localStorage', e)
      }
    }
  }

  function clearAnalysis() {
    currentAnalysis.value = null
    error.value = null
  }

  return {
    currentAnalysis,
    loading,
    error,
    history,
    hasAnalysis,
    verdictClass,
    verdictColor,
    setAnalysis,
    clearAnalysis,
  }
})
