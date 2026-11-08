import {MAIN_SECTIONS,sectionFor} from '@/lib/navigationSections';
import {VIEWS,VIEW_BY_ID} from '@/lib/views';
test('every view retains a defined main area and device aliases preserve context',()=>{
 const ids=MAIN_SECTIONS.map(section=>section.id);for(const view of VIEWS)expect(ids).toContain(sectionFor(view));
 expect(sectionFor(VIEW_BY_ID['company-blueprints'])).toBe('devices');expect(sectionFor(VIEW_BY_ID['sspr'])).toBe('home');
 expect(VIEW_BY_ID['fleet'].canonical).toBe('devices');expect(VIEW_BY_ID['assignment'].canonical).toBe('devices');
});
