import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { VALID_VIEWS, VIEW_BY_ID } from '@/lib/views';

export async function generateMetadata({ params }: { params: Promise<{ view: string }> }): Promise<Metadata> {
  const { view } = await params;
  return { title: `${VIEW_BY_ID[VALID_VIEWS.has(view) ? view : 'dashboard'].name} — OpenDirectory` };
}

export default function ViewLayout({ children }: { children: ReactNode }) {
  return children;
}
