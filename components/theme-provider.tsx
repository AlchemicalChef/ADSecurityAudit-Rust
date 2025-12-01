/**
 * Theme Provider Component
 *
 * Wraps the application with theme context for light/dark mode support.
 * Uses next-themes for seamless theme switching and persistence.
 *
 * @module components/theme-provider
 *
 * Features:
 * - Light, dark, and system theme options
 * - Automatic theme detection from system preferences
 * - Theme persistence in localStorage
 * - No flash of wrong theme on load
 *
 * CSS Variable Approach:
 * Themes are implemented using CSS custom properties, allowing
 * all components to adapt without individual styling logic.
 *
 * @see https://github.com/pacocoursey/next-themes
 */
'use client'

import * as React from 'react'
import {
  ThemeProvider as NextThemesProvider,
  type ThemeProviderProps,
} from 'next-themes'

export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>
}
