'use client'

import { useState, useCallback } from 'react'

/**
 * Hook for managing a Set-based toggle state
 * Commonly used for tracking expanded/collapsed items in lists
 *
 * @param initialValues - Initial set of values (default: empty set)
 * @returns Object with set, toggle, add, remove, clear, and has methods
 *
 * @example
 * ```tsx
 * const { set, toggle, has } = useToggleSet<number>()
 *
 * // In a list item
 * <button onClick={() => toggle(item.id)}>
 *   {has(item.id) ? 'Collapse' : 'Expand'}
 * </button>
 * ```
 */
export function useToggleSet<T>(initialValues: T[] = []) {
  const [set, setSet] = useState<Set<T>>(new Set(initialValues))

  const toggle = useCallback((value: T) => {
    setSet((prev) => {
      const next = new Set(prev)
      if (next.has(value)) {
        next.delete(value)
      } else {
        next.add(value)
      }
      return next
    })
  }, [])

  const add = useCallback((value: T) => {
    setSet((prev) => new Set(prev).add(value))
  }, [])

  const remove = useCallback((value: T) => {
    setSet((prev) => {
      const next = new Set(prev)
      next.delete(value)
      return next
    })
  }, [])

  const clear = useCallback(() => {
    setSet(new Set())
  }, [])

  const has = useCallback((value: T) => set.has(value), [set])

  return {
    set,
    toggle,
    add,
    remove,
    clear,
    has,
    size: set.size,
  }
}
