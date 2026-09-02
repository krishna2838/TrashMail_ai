import axios from 'axios'

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 30000,
})

export async function analyzeEmail(payload, isMultipart = false) {
  if (isMultipart) {
    const response = await api.post('/api/analyze', payload, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  } else {
    const response = await api.post('/api/analyze', payload, {
      headers: { 'Content-Type': 'application/json' }
    })
    return response.data
  }
}

export async function analyzeBatch(formData) {
  const response = await api.post('/api/analyze/batch', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  })
  return response.data
}

export async function getModelInfo() {
  const response = await api.get('/api/model-info')
  return response.data
}

export async function getGraph(emailHash, depth = 2) {
  const response = await api.get(`/api/graph/${emailHash}`, {
    params: { depth }
  })
  return response.data
}

export async function getRelatedEmails(emailHash) {
  const response = await api.get(`/api/graph/${emailHash}/related`)
  return response.data
}

export async function chatExplain(emailHash, analysis = null) {
  const payload = {}
  if (emailHash) payload.email_hash = emailHash
  if (analysis) payload.analysis = analysis
  const response = await api.post('/api/chat/explain', payload)
  return response.data
}

export async function chatAsk(message) {
  const response = await api.post('/api/chat/ask', { message })
  return response.data
}

export async function getHistory(limit = 50) {
  const response = await api.get('/api/history', { params: { limit } })
  return response.data
}

export async function getHistoryItem(emailHash) {
  const response = await api.get(`/api/history/${emailHash}`)
  return response.data
}

export function getReportUrl(emailHash) {
  return `http://localhost:8000/api/reports/${emailHash}.pdf`
}


export default api
