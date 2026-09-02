<template>
  <div class="card map-card">
    <div class="card-header">
      <div class="title-with-icon">
        <MapPin :size="20" class="header-icon" />
        <h2>Sender Geolocation & Infrastructure</h2>
      </div>
      <span v-if="originGeo && originGeo.country_code" class="country-badge">
        {{ originGeo.country_code }}
      </span>
    </div>

    <!-- If Origin Geo exists and has coordinates -->
    <div v-if="hasCoordinates" class="map-container-wrapper">
      <div class="geo-meta-grid">
        <div class="meta-item">
          <span class="meta-label">Origin IP</span>
          <span class="meta-val mono">{{ originGeo.ip }}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Location</span>
          <span class="meta-val">{{ locationString }}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">ASN / Organization</span>
          <span class="meta-val">{{ originGeo.asn_org || 'N/A' }}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">VT Reputation</span>
          <span :class="['rep-val', isMalicious ? 'rep-malicious' : 'rep-clean']">
            {{ isMalicious ? `Malicious (${maliciousCount} vendors)` : 'Clean / Low Risk' }}
          </span>
        </div>
      </div>

      <div ref="mapContainer" class="leaflet-map"></div>
    </div>

    <!-- Empty State -->
    <div v-else class="empty-geo-state">
      <Globe :size="32" class="empty-icon" />
      <p class="empty-title">No Public Originating IP Identified</p>
      <p class="empty-desc">
        The email headers contain only internal or private network hops. Geolocation is unavailable.
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, onBeforeUnmount } from 'vue'
import { MapPin, Globe } from 'lucide-vue-next'
import L from 'leaflet'

const props = defineProps({
  originGeo: {
    type: Object,
    default: null,
  },
  threatIntel: {
    type: Object,
    default: null,
  },
})

const mapContainer = ref(null)
let mapInstance = null

const hasCoordinates = computed(() => {
  return (
    props.originGeo &&
    typeof props.originGeo.latitude === 'number' &&
    typeof props.originGeo.longitude === 'number'
  )
})

const locationString = computed(() => {
  if (!props.originGeo) return 'Unknown'
  const parts = []
  if (props.originGeo.city) parts.push(props.originGeo.city)
  if (props.originGeo.country) parts.push(props.originGeo.country)
  return parts.join(', ') || 'Unknown'
})

const isMalicious = computed(() => {
  const ipRep = props.threatIntel?.originating_ip_reputation
  return ipRep?.reputation === 'malicious'
})

const maliciousCount = computed(() => {
  return props.threatIntel?.originating_ip_reputation?.malicious || 0
})

function initMap() {
  if (!hasCoordinates.value || !mapContainer.value) return

  // Destroy previous instance if re-rendering
  if (mapInstance) {
    mapInstance.remove()
    mapInstance = null
  }

  const lat = props.originGeo.latitude
  const lng = props.originGeo.longitude

  mapInstance = L.map(mapContainer.value, {
    zoomControl: true,
    scrollWheelZoom: false,
  }).setView([lat, lng], 5)

  // OpenStreetMap standard tiles
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 18,
  }).addTo(mapInstance)

  // Custom marker color depending on threat reputation
  const markerColor = isMalicious.value ? '#B91C1C' : '#1D4ED8'
  const customIcon = L.divIcon({
    className: 'custom-map-pin',
    html: `
      <div style="
        background-color: ${markerColor};
        width: 24px;
        height: 24px;
        border-radius: 50%;
        border: 3px solid #FFFFFF;
        box-shadow: 0 2px 6px rgba(0,0,0,0.3);
      "></div>
    `,
    iconSize: [24, 24],
    iconAnchor: [12, 12],
    popupAnchor: [0, -12],
  })

  const marker = L.marker([lat, lng], { icon: customIcon }).addTo(mapInstance)

  const popupContent = `
    <div style="font-family: sans-serif; font-size: 13px; line-height: 1.4;">
      <strong>IP:</strong> ${props.originGeo.ip || 'N/A'}<br/>
      <strong>Location:</strong> ${locationString.value}<br/>
      <strong>ASN:</strong> ${props.originGeo.asn_org || 'N/A'}<br/>
      <strong>Status:</strong> <span style="color: ${isMalicious.value ? '#B91C1C' : '#15803D'}; font-weight: 600;">
        ${isMalicious.value ? 'Malicious' : 'Clean'}
      </span>
    </div>
  `

  marker.bindPopup(popupContent).openPopup()
}

onMounted(() => {
  if (hasCoordinates.value) {
    initMap()
  }
})

watch(
  () => props.originGeo,
  () => {
    if (hasCoordinates.value) {
      setTimeout(() => initMap(), 100)
    }
  },
  { deep: true }
)

onBeforeUnmount(() => {
  if (mapInstance) {
    mapInstance.remove()
    mapInstance = null
  }
})
</script>

<style scoped>
.map-card {
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

.country-badge {
  background-color: var(--bg-page);
  color: var(--text-main);
  font-weight: 600;
  font-size: 0.8rem;
  padding: 3px 10px;
  border-radius: 9999px;
  border: 1px solid var(--border-light);
}

.map-container-wrapper {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.geo-meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  background-color: var(--bg-page);
  border-radius: 8px;
  padding: 12px 16px;
}

.meta-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.meta-label {
  font-size: 0.78rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.meta-val {
  font-size: 0.9rem;
  color: var(--text-main);
  font-weight: 500;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.rep-val {
  font-size: 0.9rem;
  font-weight: 600;
}

.rep-clean {
  color: var(--verdict-safe);
}

.rep-malicious {
  color: var(--verdict-phish);
}

.leaflet-map {
  height: 280px;
  width: 100%;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--border-light);
}

.empty-geo-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  text-align: center;
  background-color: var(--bg-page);
  border-radius: 8px;
}

.empty-icon {
  color: var(--text-light);
  margin-bottom: 12px;
}

.empty-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-main);
  margin-bottom: 4px;
}

.empty-desc {
  font-size: 0.88rem;
  color: var(--text-muted);
  max-width: 400px;
}
</style>
