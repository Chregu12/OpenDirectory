import MfaRecoveryView from '@/components/views/MfaRecoveryView';

export default async function MfaEnrollmentPage({ searchParams }: { searchParams: Promise<{ username?: string }> }) {
  const params = await searchParams;
  const username = typeof params.username === 'string' && params.username.length <= 255 ? params.username : '';
  return <MfaRecoveryView enrollment initialUsername={username} />;
}
