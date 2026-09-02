import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'
import 'vis-network/styles/vis-network.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)

app.mount('#app')
