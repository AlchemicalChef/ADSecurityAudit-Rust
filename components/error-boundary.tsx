'use client'

import React, { Component, ReactNode } from 'react'
import { AlertTriangle, X, RefreshCw } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  dismissed: boolean
  lastErrorMessage: string | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, dismissed: false, lastErrorMessage: null }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    // Only return the error state, don't reset dismissed
    return { hasError: true, error }
  }

  componentDidUpdate(prevProps: Props, prevState: State) {
    // If a new different error occurred, reset dismissed state
    if (this.state.error && this.state.error.message !== this.state.lastErrorMessage) {
      this.setState({
        dismissed: false,
        lastErrorMessage: this.state.error.message
      })
    }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo)
  }

  handleDismiss = () => {
    this.setState({ dismissed: true })
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, dismissed: false, lastErrorMessage: null })
  }

  render() {
    if (this.state.hasError && !this.state.dismissed) {
      return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-border bg-card p-6 shadow-lg mx-4">
            <div className="flex justify-end mb-2">
              <button
                onClick={this.handleDismiss}
                className="p-1 rounded hover:bg-accent transition-colors"
                title="Dismiss error"
              >
                <X className="h-5 w-5 text-muted-foreground" />
              </button>
            </div>

            <div className="flex flex-col items-center text-center">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-8 w-8 text-destructive" />
              </div>

              <h2 className="mb-2 text-xl font-semibold text-foreground">
                Something went wrong
              </h2>

              <p className="mb-4 text-sm text-muted-foreground">
                An error occurred. You can dismiss this and continue, or try again.
              </p>

              {this.state.error?.message && (
                <div className="mb-6 w-full rounded-md bg-muted p-3 max-h-32 overflow-auto">
                  <p className="text-xs font-mono text-muted-foreground break-all">
                    {this.state.error.message}
                  </p>
                </div>
              )}

              <div className="flex gap-3">
                <button
                  onClick={this.handleRetry}
                  className="inline-flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <RefreshCw className="h-4 w-4" />
                  Try Again
                </button>

                <button
                  onClick={this.handleDismiss}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-border bg-background px-4 py-2 text-sm font-medium text-foreground hover:bg-accent transition-colors"
                >
                  <X className="h-4 w-4" />
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
