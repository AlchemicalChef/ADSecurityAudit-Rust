/**
 * Root Layout Component
 *
 * Next.js root layout providing HTML structure, metadata, and global styles.
 * This component wraps all pages in the application.
 *
 * @module app/layout
 *
 * Metadata:
 * - Title: ADSecurityScanner
 * - Description: Active Directory Security Scanner
 * - Icons: Light/dark mode aware favicons
 *
 * Global Features:
 * - Font configuration (sans-serif)
 * - CSS reset via globals.css
 * - Theme-aware icon switching
 */

import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ADSecurityScanner',
  description: 'Active Directory Security Scanner',
  icons: {
    icon: [
      {
        url: '/icon-light-32x32.png',
        media: '(prefers-color-scheme: light)',
      },
      {
        url: '/icon-dark-32x32.png',
        media: '(prefers-color-scheme: dark)',
      },
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
    apple: '/apple-icon.png',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        {children}
      </body>
    </html>
  )
}
