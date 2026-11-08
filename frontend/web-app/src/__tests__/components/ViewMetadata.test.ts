import { generateMetadata } from '@/app/[view]/layout';

describe('view metadata', () => {
  test.each([
    ['users', 'Mitarbeitende — OpenDirectory'],
    ['licenses', 'Lizenzverwaltung — OpenDirectory'],
    ['fleet', 'Erweiterte Geräteansicht — OpenDirectory'],
    ['unknown-view', 'Übersicht — OpenDirectory'],
    ['__proto__', 'Übersicht — OpenDirectory'],
  ])('returns a safe title for %s', async (view, title) => {
    await expect(generateMetadata({ params: Promise.resolve({ view }) })).resolves.toEqual({ title });
  });
});
