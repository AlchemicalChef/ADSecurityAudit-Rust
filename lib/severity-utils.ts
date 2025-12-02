/**
 * Severity Utilities
 *
 * Shared utilities for handling severity levels across audit components.
 * Provides consistent styling and classification for security findings.
 *
 * @module lib/severity-utils
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Get Tailwind CSS classes for a severity badge
 *
 * @param severity - The severity level (case-insensitive)
 * @returns Tailwind CSS classes for background, text, and border colors
 *
 * @example
 * ```tsx
 * <Badge className={getSeverityColor(finding.severity)}>
 *   {finding.severity}
 * </Badge>
 * ```
 */
export function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/20 text-red-400 border-red-500/50'
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/50'
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
    case 'low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/50'
    case 'info':
      return 'bg-gray-500/20 text-gray-400 border-gray-500/50'
    default:
      return 'bg-muted text-muted-foreground border-border'
  }
}

/**
 * Get text color class for a severity level
 *
 * @param severity - The severity level (case-insensitive)
 * @returns Tailwind CSS text color class
 */
export function getSeverityTextColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'text-red-400'
    case 'high':
      return 'text-orange-400'
    case 'medium':
      return 'text-yellow-400'
    case 'low':
      return 'text-blue-400'
    case 'info':
      return 'text-gray-400'
    default:
      return 'text-muted-foreground'
  }
}

/**
 * Get risk level label and color from a numeric score
 *
 * @param score - Risk score (0-100)
 * @returns Object with label and color class
 *
 * @example
 * ```tsx
 * const risk = getRiskLevel(finding.score)
 * <span className={risk.color}>{risk.label}</span>
 * ```
 */
export function getRiskLevel(score: number): { label: string; color: string } {
  if (score >= 70) return { label: 'Critical', color: 'text-red-400' }
  if (score >= 50) return { label: 'High', color: 'text-orange-400' }
  if (score >= 30) return { label: 'Medium', color: 'text-yellow-400' }
  return { label: 'Low', color: 'text-green-400' }
}

/**
 * Get severity order for sorting (higher = more severe)
 *
 * @param severity - The severity level
 * @returns Numeric order value
 */
export function getSeverityOrder(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 4
    case 'high':
      return 3
    case 'medium':
      return 2
    case 'low':
      return 1
    case 'info':
      return 0
    default:
      return -1
  }
}

/**
 * Sort items by severity (critical first)
 *
 * @param items - Array of items with a severity property
 * @param getSeverity - Function to extract severity from an item
 * @returns New array sorted by severity
 */
export function sortBySeverity<T>(
  items: T[],
  getSeverity: (item: T) => string
): T[] {
  return [...items].sort(
    (a, b) => getSeverityOrder(getSeverity(b)) - getSeverityOrder(getSeverity(a))
  )
}

/**
 * Count findings by severity level
 *
 * @param items - Array of items with a severity property
 * @param getSeverity - Function to extract severity from an item
 * @returns Object with counts for each severity level
 */
export function countBySeverity<T>(
  items: T[],
  getSeverity: (item: T) => string
): Record<SeverityLevel | 'unknown', number> {
  const counts: Record<SeverityLevel | 'unknown', number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  }

  for (const item of items) {
    const severity = getSeverity(item).toLowerCase() as SeverityLevel
    if (severity in counts) {
      counts[severity]++
    } else {
      counts.unknown++
    }
  }

  return counts
}
