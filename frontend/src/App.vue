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
/*
 * Shell scroll model (Phase 25):
 *   .app-layout  — fixed viewport height, never scrolls itself
 *   sidebar      — fixed inside the shell, scrolls internally only if it
 *                  ever exceeds viewport height
 *   .app-body    — the ONE scrolling container: page content and the model
 *                  info footer scroll together inside here
 *
 * Result: scrolling any page never moves the sidebar, and there is only
 * one scrollbar (the app-body's), never a double-scrollbar.
 */
.app-layout {
  height: 100vh;
  display: flex;
  align-items: stretch;
  overflow: hidden;
}

.app-body {
  flex: 1;
  min-width: 0;
  height: 100vh;
  overflow-y: auto;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
}

.main-content {
  flex: 1;
  width: 100%;
  min-width: 0;
}

@media print {
  /* Print flow needs the shell to lay out naturally — undo the fixed
   * viewport height and scroll containment so multi-page reports render
   * correctly. The sidebar's own @media print rule (Phase 21) still hides
   * it in print. */
  .app-layout,
  .app-body {
    height: auto;
    overflow: visible;
  }
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
