/**
 * Utility Functions Module
 *
 * Common utility functions used throughout the application.
 *
 * @module lib/utils
 *
 * Functions:
 * - cn: Conditional class name merging for Tailwind CSS
 *
 * The `cn` function combines clsx (conditional classes) with
 * tailwind-merge (conflict resolution) for optimal className handling.
 *
 * @example
 * ```typescript
 * import { cn } from '@/lib/utils'
 *
 * // Merge classes with conflict resolution
 * cn('px-4 py-2', isActive && 'bg-blue-500', 'bg-gray-500')
 * // Result: 'px-4 py-2 bg-blue-500' (gray overridden by blue)
 * ```
 */

import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merges class names with Tailwind CSS conflict resolution.
 *
 * @param inputs - Class values (strings, arrays, objects, conditionals)
 * @returns Merged class string with conflicts resolved
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
