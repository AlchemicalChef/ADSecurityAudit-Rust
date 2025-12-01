/**
 * Error Page Component
 *
 * Next.js error boundary for route-level error handling.
 * Displays when an error occurs within a specific route segment.
 *
 * @module app/error
 *
 * Features:
 * - Error message display (development mode)
 * - "Try Again" button for component re-render
 * - "Reload App" button for full page refresh
 * - Styled error UI consistent with app theme
 *
 * Error Logging:
 * - Errors logged to console for debugging
 * - Error digest available for error tracking
 *
 * Recovery Options:
 * - reset(): Re-renders the error boundary children
 * - reload(): Full page refresh via window.location
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/error-handling
 */
'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw, Home } from 'lucide-react'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Log the error to console for debugging
    console.error('Application error:', error)
  }, [error])

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-card p-6 shadow-lg">
        <div className="flex flex-col items-center text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
            <AlertTriangle className="h-8 w-8 text-destructive" />
          </div>

          <h2 className="mb-2 text-xl font-semibold text-foreground">
            Something went wrong
          </h2>

          <p className="mb-6 text-sm text-muted-foreground">
            An error occurred while loading this page. You can try again or return to the dashboard.
          </p>

          {error.message && (
            <div className="mb-6 w-full rounded-md bg-muted p-3">
              <p className="text-xs font-mono text-muted-foreground break-all">
                {error.message}
              </p>
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => reset()}
              className="inline-flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
              Try Again
            </button>

            <button
              onClick={() => window.location.reload()}
              className="inline-flex items-center justify-center gap-2 rounded-md border border-border bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent transition-colors"
            >
              <Home className="h-4 w-4" />
              Reload App
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
