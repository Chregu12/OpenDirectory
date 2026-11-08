import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'OpenDirectory',
  description: 'Integrated identity management and monitoring platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="de" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: "try{var t=localStorage.getItem('theme');document.documentElement.setAttribute('data-theme',t==='light'||t==='dark'?t:matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch{}" }} />
      </head>
      <body className="font-sans">{children}</body>
    </html>
  )
}
