import { createRouter, createWebHistory } from 'vue-router'
import AnalyzeView from '../views/AnalyzeView.vue'
import ResultsView from '../views/ResultsView.vue'
import HistoryView from '../views/HistoryView.vue'

const routes = [
  {
    path: '/',
    name: 'analyze',
    component: AnalyzeView,
  },
  {
    path: '/results',
    name: 'results',
    component: ResultsView,
  },
  {
    path: '/history',
    name: 'history',
    component: HistoryView,
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
