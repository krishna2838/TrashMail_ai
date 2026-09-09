import { onBeforeUnmount } from 'vue'
import { Network as VisNetwork, DataSet } from 'vis-network/standalone'

/**
 * Shared vis-network setup used by NetworkGraphPanel (single-email / batch
 * embedded panel) and ClustersView (full-page cross-database view).
 *
 * Owns node/edge styling, physics options, the stabilization → freeze fix
 * from Phase 15 (prevents infinite jitter), fit-on-mount, and an optional
 * ResizeObserver so the canvas re-fits on container size changes.
 */

function getNodeColor(node) {
  if (node.type === 'email') {
    if (node.verdict === 'Safe') {
      return {
        background: '#F0FDF4', border: '#15803D',
        highlight: { background: '#DCFCE7', border: '#15803D' },
        hover: { background: '#DCFCE7', border: '#15803D' },
      }
    } else if (node.verdict === 'Suspicious') {
      return {
        background: '#FFFBEB', border: '#B45309',
        highlight: { background: '#FEF3C7', border: '#B45309' },
        hover: { background: '#FEF3C7', border: '#B45309' },
      }
    } else {
      return {
        background: '#FEF2F2', border: '#B91C1C',
        highlight: { background: '#FEE2E2', border: '#B91C1C' },
        hover: { background: '#FEE2E2', border: '#B91C1C' },
      }
    }
  } else if (node.type === 'domain') {
    return { background: '#EFF6FF', border: '#1D4ED8', highlight: { background: '#DBEAFE', border: '#1D4ED8' }, hover: { background: '#DBEAFE', border: '#1D4ED8' } }
  } else if (node.type === 'upi') {
    return { background: '#F5F3FF', border: '#7C3AED', highlight: { background: '#EDE9FE', border: '#7C3AED' }, hover: { background: '#EDE9FE', border: '#7C3AED' } }
  } else if (node.type === 'wallet') {
    return { background: '#FFFBEB', border: '#D97706', highlight: { background: '#FEF3C7', border: '#D97706' }, hover: { background: '#FEF3C7', border: '#D97706' } }
  } else if (node.type === 'attachment_hash') {
    return { background: '#FFF1F2', border: '#E11D48', highlight: { background: '#FFE4E6', border: '#E11D48' }, hover: { background: '#FFE4E6', border: '#E11D48' } }
  } else if (node.type === 'template_hash') {
    return { background: '#F0FDFA', border: '#0D9488', highlight: { background: '#CCFBF1', border: '#0D9488' }, hover: { background: '#CCFBF1', border: '#0D9488' } }
  }
  return { background: '#F3F4F6', border: '#4B5563', highlight: { background: '#E5E7EB', border: '#374151' }, hover: { background: '#E5E7EB', border: '#374151' } }
}

function nodeShape(type) {
  if (type === 'domain') return 'ellipse'
  if (type === 'ip') return 'database'
  if (type === 'upi') return 'diamond'
  if (type === 'wallet') return 'hexagon'
  return 'box'
}

export function useNetworkGraph(options = {}) {
  const {
    height = '380px',
    resize = true,
    onNodeClick = null,
  } = options

  let networkInstance = null
  let resizeObserver = null
  let container = null
  let heightPx = height
  let nodesDataSet = null
  let edgesDataSet = null
  let baseNodeStyles = new Map()
  let baseEdgeStyles = new Map()

  function setSize() {
    if (networkInstance) networkInstance.setSize('100%', heightPx)
  }

  function fit(animate = true) {
    if (!networkInstance) return
    networkInstance.fit(
      animate
        ? { animation: { duration: 350, easingFunction: 'easeInOutQuad' } }
        : undefined
    )
  }

  function render(containerEl, graphData, opts = {}) {
    if (!containerEl) return
    container = containerEl
    if (opts.height) heightPx = opts.height

    const nodesRaw = (graphData && graphData.nodes) || []
    const edgesRaw = (graphData && graphData.edges) || []

    if (nodesRaw.length === 0) {
      if (networkInstance) {
        networkInstance.destroy()
        networkInstance = null
      }
      return
    }

    const highlightId = opts.highlightId || null

    const visNodes = nodesRaw.map((n) => {
      const colorScheme = getNodeColor(n)
      const isCurrent = highlightId && n.id === highlightId
      let labelText = n.label || n.id
      if (n.type === 'email' && labelText.length > 28) {
        labelText = labelText.slice(0, 25) + '...'
      }
      return {
        id: n.id,
        label: labelText,
        title: `${(n.type || 'node').toUpperCase()}: ${n.label || n.id}${n.verdict ? ` [${n.verdict}]` : ''}`,
        shape: nodeShape(n.type),
        margin: { top: 8, bottom: 8, left: 12, right: 12 },
        borderWidth: isCurrent ? 3 : 1.5,
        color: colorScheme,
        font: {
          face: 'Inter, system-ui, -apple-system, sans-serif',
          size: isCurrent ? 13 : 12,
          color: '#111827',
          bold: isCurrent,
        },
        shadow: {
          enabled: true, color: 'rgba(0,0,0,0.06)', size: 4, x: 1, y: 2,
        },
      }
    })

    const visEdges = edgesRaw.map((e, idx) => ({
      id: `edge-${idx}`,
      from: e.source,
      to: e.target,
      label: e.type,
      arrows: { to: { enabled: true, scaleFactor: 0.7 } },
      color: { color: '#9CA3AF', highlight: '#1D4ED8', hover: '#1D4ED8', opacity: 0.9 },
      font: {
        size: 10, color: '#6B7280', face: 'Inter, system-ui, sans-serif',
        align: 'horizontal', background: '#FFFFFF', strokeWidth: 0,
      },
      smooth: { type: 'cubicBezier', roundness: 0.25 },
    }))

    nodesDataSet = new DataSet(visNodes)
    edgesDataSet = new DataSet(visEdges)
    baseNodeStyles = new Map(visNodes.map(n => [n.id, { color: n.color, font: n.font }]))
    baseEdgeStyles = new Map(visEdges.map(e => [e.id, { color: e.color }]))
    const networkData = { nodes: nodesDataSet, edges: edgesDataSet }

    const visOptions = {
      autoResize: true,
      height: '100%',
      width: '100%',
      layout: { improvedLayout: true },
      physics: {
        enabled: true,
        solver: 'barnesHut',
        barnesHut: {
          gravitationalConstant: -2500,
          centralGravity: 0.25,
          springLength: 130,
          springConstant: 0.04,
          damping: 0.09,
          avoidOverlap: 0.5,
        },
        stabilization: {
          enabled: true,
          iterations: 200,
          updateInterval: 25,
          fit: true,
        },
      },
      interaction: {
        hover: true,
        hoverConnectedEdges: true,
        tooltipDelay: 150,
        zoomView: true,
        dragView: true,
      },
    }

    if (networkInstance) {
      networkInstance.destroy()
      networkInstance = null
    }

    networkInstance = new VisNetwork(container, networkData, visOptions)

    // Phase 15 physics-freeze fix: freeze physics once stabilization completes
    // to prevent infinite jitter, then fit to view.
    networkInstance.once('stabilizationIterationsDone', () => {
      if (networkInstance) {
        networkInstance.setOptions({ physics: false })
        networkInstance.fit({ animation: { duration: 350, easingFunction: 'easeInOutQuad' } })
      }
    })
    networkInstance.once('stabilized', () => {
      if (networkInstance) networkInstance.setOptions({ physics: false })
    })
    networkInstance.once('afterDrawing', () => {
      if (networkInstance) networkInstance.fit()
    })

    // Fallback re-fit after DOM settles
    setTimeout(() => {
      if (networkInstance) {
        networkInstance.redraw()
        networkInstance.fit()
      }
    }, 250)

    if (onNodeClick) {
      networkInstance.on('click', (params) => {
        if (params.nodes && params.nodes.length > 0) {
          onNodeClick(params.nodes[0])
        } else {
          onNodeClick(null)
        }
      })
    }

    if (resize && !resizeObserver && window.ResizeObserver && container) {
      resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          if (entry.contentRect.width > 20 && entry.contentRect.height > 20) {
            if (networkInstance) {
              networkInstance.setSize('100%', heightPx)
              networkInstance.redraw()
              networkInstance.fit()
            }
          }
        }
      })
      resizeObserver.observe(container)
    }
  }

  /**
   * Highlight a subset of node IDs; dim the rest. Only visual style is
   * updated via DataSet.update() — no re-render, no physics restart, so the
   * Phase 15 stabilization-freeze is preserved.
   *
   * Pass null (or an empty set) to restore all nodes/edges to their base
   * styling.
   */
  function setHighlight(nodeIdSet) {
    if (!networkInstance || !nodesDataSet || !edgesDataSet) return
    const active = nodeIdSet && (nodeIdSet.size || nodeIdSet.length) ? nodeIdSet : null
    const has = (id) => (active instanceof Set ? active.has(id) : (Array.isArray(active) ? active.includes(id) : false))

    const nodeUpdates = []
    for (const [id, base] of baseNodeStyles.entries()) {
      if (!active || has(id)) {
        nodeUpdates.push({ id, color: base.color, font: base.font, opacity: 1 })
      } else {
        nodeUpdates.push({
          id,
          opacity: 0.18,
          font: { ...base.font, color: 'rgba(17,24,39,0.35)' },
        })
      }
    }
    nodesDataSet.update(nodeUpdates)

    const edgeUpdates = []
    for (const [id, base] of baseEdgeStyles.entries()) {
      const edge = edgesDataSet.get(id)
      if (!edge) continue
      const bothIn = !active || (has(edge.from) && has(edge.to))
      if (bothIn) {
        edgeUpdates.push({ id, color: base.color })
      } else {
        edgeUpdates.push({
          id,
          color: { color: 'rgba(156,163,175,0.18)', highlight: 'rgba(156,163,175,0.18)', hover: 'rgba(156,163,175,0.18)', opacity: 0.18 },
        })
      }
    }
    edgesDataSet.update(edgeUpdates)
  }

  function clearHighlight() {
    setHighlight(null)
  }

  /**
   * Center the view on a single node without restarting physics — visual
   * pan/zoom only, node positions are not changed.
   */
  function focusNode(nodeId, opts = {}) {
    if (!networkInstance || !nodeId) return
    try {
      networkInstance.focus(nodeId, {
        scale: opts.scale ?? 1.1,
        animation: opts.animation ?? { duration: 350, easingFunction: 'easeInOutQuad' },
      })
    } catch (e) {
      // ignore — vis-network throws if the id is not in the current dataset
    }
  }

  function destroy() {
    if (resizeObserver) {
      resizeObserver.disconnect()
      resizeObserver = null
    }
    if (networkInstance) {
      networkInstance.destroy()
      networkInstance = null
    }
  }

  onBeforeUnmount(destroy)

  return { render, fit, setSize, destroy, setHighlight, clearHighlight, focusNode }
}
