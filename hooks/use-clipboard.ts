'use client'

import { useState, useCallback } from 'react'

/**
 * Hook for clipboard operations with copy feedback
 *
 * @param resetDelay - Delay in ms before resetting copied state (default: 2000)
 * @returns Object with copyToClipboard function and copiedValue state
 *
 * @example
 * ```tsx
 * const { copyToClipboard, copiedValue } = useClipboard()
 *
 * <button onClick={() => copyToClipboard(item.value, item.id)}>
 *   {copiedValue === item.id ? 'Copied!' : 'Copy'}
 * </button>
 * ```
 */
export function useClipboard<T = string>(resetDelay: number = 2000) {
  const [copiedValue, setCopiedValue] = useState<T | null>(null)

  const copyToClipboard = useCallback(
    async (text: string, identifier?: T) => {
      try {
        await navigator.clipboard.writeText(text)
        setCopiedValue(identifier ?? (text as unknown as T))
        setTimeout(() => setCopiedValue(null), resetDelay)
        return true
      } catch {
        console.error('Failed to copy to clipboard')
        return false
      }
    },
    [resetDelay]
  )

  const isCopied = useCallback(
    (identifier: T) => copiedValue === identifier,
    [copiedValue]
  )

  return {
    copyToClipboard,
    copiedValue,
    isCopied,
    reset: () => setCopiedValue(null),
  }
}
