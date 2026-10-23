import MfaRecoveryView from '@/components/views/MfaRecoveryView';

export default function MfaEnrollmentPage({ searchParams }: { searchParams?: { username?: string } }) {
  const username = typeof searchParams?.username === 'string' && searchParams.username.length <= 255 ? searchParams.username : '';
  return <MfaRecoveryView enrollment initialUsername={username} />;
}
