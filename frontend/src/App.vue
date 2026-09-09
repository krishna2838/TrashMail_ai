<template>
  <div class="app-layout">
    <AppSidebar />

    <div class="app-body">
      <main class="main-content">
        <router-view v-slot="{ Component }">
          <Transition name="route-fade" mode="out-in">
            <component :is="Component" />
          </Transition>
        </router-view>
      </main>
      <ModelInfoFooter />
    </div>
  </div>
</template>

<script setup>
import AppSidebar from './components/AppSidebar.vue'
import ModelInfoFooter from './components/ModelInfoFooter.vue'
</script>

<style scoped>
.app-layout {
  min-height: 100vh;
  display: flex;
  align-items: stretch;
}

.app-body {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.main-content {
  flex: 1;
  width: 100%;
}

.route-fade-enter-active,
.route-fade-leave-active {
  transition: opacity 0.18s ease;
}

.route-fade-enter-from,
.route-fade-leave-to {
  opacity: 0;
}
</style>
