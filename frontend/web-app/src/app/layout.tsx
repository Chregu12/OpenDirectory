import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'OpenDirectory - Service Integration Dashboard',
  description: 'Integrated identity management and monitoring platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="font-sans">{children}</body>
    </html>
  )
}