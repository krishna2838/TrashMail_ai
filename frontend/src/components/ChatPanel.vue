<template>
  <div class="card chat-card">
    <div class="card-header">
      <div class="title-with-icon">
        <MessageCircle :size="20" class="header-icon" />
        <h2>Scam Query Assistant</h2>
      </div>
      <span class="chat-mode-label">{{ modeLabel }}</span>
    </div>
    <p class="section-desc">
      {{ modeDescription }}
    </p>

    <!-- Message History -->
    <div ref="chatContainer" class="messages-container">
      <div 
        v-for="(msg, idx) in messages" 
        :key="idx" 
        :class="['message-bubble-wrapper', msg.sender === 'user' ? 'wrapper-user' : 'wrapper-assistant']"
      >
        <div :class="['message-bubble', msg.sender === 'user' ? 'bubble-user' : 'bubble-assistant']">
          <div class="bubble-text" v-html="formatMessage(msg.text)"></div>
        </div>
      </div>

      <!-- Loading dots -->
      <div v-if="isLoading" class="message-bubble-wrapper wrapper-assistant">
        <div class="message-bubble bubble-assistant bubble-loading">
          <div class="dot-typing">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>
      </div>

      <!-- 503 / Service Error message -->
      <div v-if="chatError" class="chat-error-banner">
        <AlertCircle :size="16" />
        <span>{{ chatError }}</span>
      </div>
    </div>

    <!-- Input Form -->
    <form class="chat-input-row" @submit.prevent="sendMessage">
      <input 
        v-model="inputQuery"
        type="text"
        :placeholder="inputPlaceholder"
        :disabled="isLoading"
        class="chat-input"
      />
      <button 
        type="submit" 
        class="btn-primary send-btn"
        :disabled="isLoading || !inputQuery.trim()"
      >
        <Send :size="16" />
        <span>Ask</span>
      </button>
    </form>
  </div>
</template>

<script setup>
import { ref, computed, nextTick } from 'vue'
import { MessageCircle, Send, AlertCircle } from 'lucide-vue-next'
import { marked } from 'marked'
import { chatAsk } from '../api/client'

// Configure marked for safe defaults — no raw HTML passthrough
marked.setOptions({
  breaks: true,
  gfm: true,
})

const props = defineProps({
  context: {
    type: Object,
    default: null,
  },
})

const chatContainer = ref(null)
const inputQuery = ref('')
const isLoading = ref(false)
const chatError = ref(null)

const isEmailContext = computed(() => {
  return Boolean(props.context && ('verdict' in props.context || 'risk_score' in props.context))
})

const isBatchContext = computed(() => {
  return Boolean(props.context && ('batch_size' in props.context || 'cluster_count' in props.context))
})

const modeLabel = computed(() => {
  if (isEmailContext.value) return 'Analysis Assistant'
  if (isBatchContext.value) return 'Batch Assistant'
  return 'Freeform Mode'
})

const modeDescription = computed(() => {
  if (isEmailContext.value) {
    return 'Ask questions about this email report or paste suspicious messages to analyze.'
  }
  if (isBatchContext.value) {
    return 'Ask questions about this batch investigation or paste suspicious messages to analyze.'
  }
  return 'Paste any suspicious message snippet, SMS, or link to ask the local AI assistant if it looks like a scam.'
})

const inputPlaceholder = computed(() => {
  if (isEmailContext.value) {
    return "e.g. 'Why was this flagged?' or paste a suspicious message..."
  }
  if (isBatchContext.value) {
    return "e.g. 'How many phishing campaigns were found?' or paste a message..."
  }
  return "e.g. 'Is this message asking for wire transfer legitimate?'"
})

const initialText = computed(() => {
  if (isEmailContext.value) {
    return 'Hello! I am your security assistant. I have the forensic findings for this email loaded. Ask me anything about this report, or paste another message to evaluate.'
  }
  if (isBatchContext.value) {
    return 'Hello! I am your security assistant. I have the batch triage findings loaded. Ask me about detected campaign clusters, or paste any message to evaluate.'
  }
  return 'Hello! I am your local security assistant. You can paste any suspicious email text, SMS message, or prompt to ask whether it appears fraudulent.'
})

const messages = ref([
  {
    sender: 'assistant',
    text: initialText.value,
  },
])

function formatMessage(text) {
  if (!text) return ''
  return marked.parse(text)
}

async function scrollToBottom() {
  await nextTick()
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight
  }
}

async function sendMessage() {
  const query = inputQuery.value.trim()
  if (!query || isLoading.value) return

  // Push user message
  messages.value.push({ sender: 'user', text: query })
  inputQuery.value = ''
  chatError.value = null
  isLoading.value = true
  scrollToBottom()

  try {
    const res = await chatAsk(query, props.context)
    messages.value.push({ sender: 'assistant', text: res.response })
  } catch (err) {
    console.error('Chat query failed', err)
    if (err.response?.status === 503) {
      chatError.value = 'Local Ollama service is unavailable. Please check that Ollama is running.'
    } else {
      chatError.value = err.response?.data?.detail || 'Failed to receive response from chat assistant.'
    }
  } finally {
    isLoading.value = false
    scrollToBottom()
  }
}
</script>

<style scoped>
.chat-card {
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

.chat-mode-label {
  font-size: 0.8rem;
  color: var(--text-muted);
  background-color: var(--bg-page);
  border: 1px solid var(--border-light);
  padding: 3px 10px;
  border-radius: 9999px;
}

.section-desc {
  font-size: 0.9rem;
  color: var(--text-muted);
  line-height: 1.5;
}

.messages-container {
  height: 280px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
  background-color: var(--bg-page);
  border-radius: 8px;
  padding: 16px;
  border: 1px solid var(--border-light);
}

.message-bubble-wrapper {
  display: flex;
  width: 100%;
}

.wrapper-user {
  justify-content: flex-end;
}

.wrapper-assistant {
  justify-content: flex-start;
}

.message-bubble {
  max-width: 80%;
  padding: 10px 16px;
  border-radius: 12px;
  font-size: 0.92rem;
  line-height: 1.5;
  word-break: break-word;
}

.bubble-user {
  background-color: var(--accent);
  color: #FFFFFF;
  border-bottom-right-radius: 2px;
}

.bubble-assistant {
  background-color: #FFFFFF;
  color: var(--text-main);
  border: 1px solid var(--border-light);
  border-bottom-left-radius: 2px;
}

.bubble-loading {
  padding: 14px 18px;
}

.dot-typing {
  display: flex;
  align-items: center;
  gap: 4px;
}

.dot-typing span {
  width: 6px;
  height: 6px;
  background-color: var(--text-light);
  border-radius: 50%;
  animation: typing 1.4s infinite ease-in-out both;
}

.dot-typing span:nth-child(1) { animation-delay: -0.32s; }
.dot-typing span:nth-child(2) { animation-delay: -0.16s; }

@keyframes typing {
  0%, 80%, 100% { transform: scale(0); }
  40% { transform: scale(1); }
}

.chat-error-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  background-color: var(--verdict-phish-bg);
  border: 1px solid var(--verdict-phish);
  color: var(--verdict-phish);
  font-size: 0.85rem;
  padding: 8px 12px;
  border-radius: 6px;
}

.chat-input-row {
  display: flex;
  gap: 10px;
}

.chat-input {
  flex: 1;
  padding: 10px 14px;
  border-radius: 8px;
  border: 1px solid var(--border-light);
  font-family: var(--font-family);
  font-size: 0.92rem;
  color: var(--text-main);
  background-color: #FFFFFF;
  outline: none;
  transition: border-color 0.15s ease;
}

.chat-input:focus {
  border-color: var(--border-focus);
}

.send-btn {
  padding: 10px 18px;
}

/* Markdown content inside chat bubbles */
.bubble-text :deep(p) {
  margin: 0 0 6px 0;
}

.bubble-text :deep(p:last-child) {
  margin-bottom: 0;
}

.bubble-text :deep(ul),
.bubble-text :deep(ol) {
  margin: 4px 0 6px 0;
  padding-left: 20px;
}

.bubble-text :deep(li) {
  margin-bottom: 2px;
}

.bubble-text :deep(strong) {
  font-weight: 600;
}

.bubble-text :deep(code) {
  background-color: rgba(0, 0, 0, 0.06);
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 0.88em;
}
</style>
