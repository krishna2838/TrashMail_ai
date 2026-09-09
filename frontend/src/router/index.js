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
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue'),
  },
  {
    path: '/results',
    name: 'results',
    component: ResultsView,
  },
  {
    path: '/batch',
    name: 'batch',
    component: () => import('../views/BatchAnalyzeView.vue'),
  },
  {
    path: '/history',
    name: 'history',
    component: HistoryView,
  },
  {
    path: '/clusters',
    name: 'clusters',
    component: () => import('../views/ClustersView.vue'),
  },
  {
    path: '/reports',
    name: 'reports',
    component: () => import('../views/ReportsView.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
