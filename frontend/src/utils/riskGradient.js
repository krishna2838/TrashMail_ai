/**
 * Return a CSS linear-gradient string for a risk-score meter fill.
 *
 * Renders a continuous green → amber → red gradient truncated to the score's
 * width. Because the caller sets the fill's `width: score%`, we scale the
 * gradient stops to that percentage so a 30-score bar shows green-to-amber
 * and a 90-score bar shows green all the way through to red.
 */
export function riskGradient(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0))
  if (s <= 0) return 'linear-gradient(90deg, #15803D 0%, #15803D 100%)'
  // Stops (as % of the FULL 0-100 scale)
  const stops = [
    { at: 0, color: '#15803D' },   // green
    { at: 45, color: '#84CC16' },  // yellow-green
    { at: 65, color: '#F59E0B' },  // amber
    { at: 85, color: '#EF4444' },  // red
    { at: 100, color: '#B91C1C' }, // deep red
  ]
  // Scale each stop into the actual filled width [0, s], so the bar visually
  // ends on the color appropriate for `s`.
  const scaled = stops.map(({ at, color }) => {
    const scaledAt = Math.min(100, (at * 100) / s)
    return `${color} ${scaledAt.toFixed(1)}%`
  })
  return `linear-gradient(90deg, ${scaled.join(', ')})`
}
