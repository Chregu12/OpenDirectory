'use client';

import React, { useEffect, useId, useRef, useState } from 'react';
import { BlueprintRecord } from '@/lib/blueprintConfiguration';
import { PolicyAccess, policyGovernance } from '@/lib/policyGovernance';
import { BlueprintPreviewPlatform, BlueprintPreviewResult, BlueprintPreviewVariant, blueprintPreview, blueprintPreviewError } from '@/lib/blueprintPreview';

interface Props { rows: BlueprintRecord[]; access: PolicyAccess }
export default function BlueprintPreviewPanel({ rows, access }: Props) {
  if (!access.permissions.includes('policies.read') || !access.permissions.includes('policies.preview')) return null;
  return <SelectedBlueprintPreview key={JSON.stringify([access.userId, access.subject, rows])} rows={rows} access={access} />;
}
function Payload({ variant, blueprints }: { variant: BlueprintPreviewVariant; blueprints: BlueprintPreviewResult['blueprints'] }) {
  return <div className="space-y-2 min-w-0">
    <ul className="text-xs space-y-2">{variant.sources.map(source => {
      const blueprint = blueprints.find(item => item.id === source.blueprintId)!;
      return <li key={source.configurationId} className="break-all">{blueprint.name} · Version {blueprint.version} · Blueprint {source.blueprintId} · Konfiguration {source.configurationId}</li>;
    })}</ul>
    <details><summary>Unverändertes Konfigurations-JSON anzeigen</summary><pre className="mt-2 text-xs whitespace-pre-wrap break-all">{variant.payloadJson}</pre></details>
  </div>;
}
function SelectedBlueprintPreview({ rows, access }: Props) {
  const contentId = useId(); const epoch = useRef(0); const controller = useRef<AbortController | null>(null); const running = useRef(false);
  const [open, setOpen] = useState(false); const [platform, setPlatform] = useState<BlueprintPreviewPlatform>('macos'); const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [result, setResult] = useState<BlueprintPreviewResult | null>(null);
  const invalidate = () => {
    epoch.current++; controller.current?.abort(); controller.current = null; running.current = false;
    setBusy(false); setResult(null); setError('');
  };
  useEffect(() => {
    const ended = () => { invalidate(); setSelected([]); setOpen(false); setError('Sitzung nicht mehr bestätigt. Berechtigungen und Katalog ausdrücklich neu laden.'); };
    window.addEventListener('od:session-error', ended);
    return () => { epoch.current++; controller.current?.abort(); running.current = false; window.removeEventListener('od:session-error', ended); };
  }, []);
  const preview = async () => {
    if (!open || running.current || !selected.length || selected.length > 25) return;
    invalidate(); const generation = epoch.current; const abort = new AbortController(); controller.current = abort; running.current = true; setBusy(true);
    const requested = { platform, blueprints: rows.filter(row => selected.includes(row.id)).map(row => ({ id: row.id, version: row.version })) };
    try {
      const current = await policyGovernance.access(abort.signal); if (generation !== epoch.current) return;
      if (current.userId !== access.userId || current.subject !== access.subject || !current.permissions.includes('policies.read') || !current.permissions.includes('policies.preview')) throw new Error('Original preview authority required');
      const response = await blueprintPreview.compare(requested, abort.signal); if (generation === epoch.current) setResult(response);
    } catch (failure) { if (generation === epoch.current) { setResult(null); setError(blueprintPreviewError(failure)); } }
    finally { if (generation === epoch.current) { running.current = false; setBusy(false); controller.current = null; } }
  };
  return <section aria-label="Ausgewählte Blueprint-Versionen vergleichen" className="rounded border border-blue-400/30 p-4 space-y-3 min-w-0">
    <button type="button" aria-expanded={open} aria-controls={contentId} onClick={() => { invalidate(); setSelected([]); setOpen(value => !value); }}>Ausgewählte Blueprint-Versionen vergleichen</button>
    {error && !open && <p role="alert">{error}</p>}
    {open && <div id={contentId} className="space-y-4">
      <h2 className="font-semibold">Nur ausgewählte aktuelle Blueprint-Versionen</h2>
      <p className="text-sm">Vergleicht nur ausgewählte aktuelle Versionen; keine Änderungen an Geräten oder Lizenzen.</p>
      <details className="text-sm space-y-2"><summary>Prüfumfang und Grenzen</summary>
        <p>Schreibgeschützte Momentaufnahme im Platform-Policy-Scope. Keine mandanteneigene Rollenfreigabe und keine unveränderliche Versionshistorie. Nur diese Auswahl, nicht alle zugewiesenen Benutzer, Gruppen oder Geräte.</p>
        <p>Konservative Prüfung: ein vollständiges Profil je Konfigurationsart. Abweichende Profile sind Konflikte; keine Priorität und kein Gewinner werden angenommen. Keine Apple-Validierung, Deployment-Freigabe, MDM-Ausführung oder Lizenzreservierung.</p>
      </details>
      <label className="block" htmlFor={`${contentId}-platform`}>Vorschau-Plattform</label>
      <select id={`${contentId}-platform`} className="block" value={platform} onChange={event => { invalidate(); setSelected([]); setPlatform(event.target.value as BlueprintPreviewPlatform); }}><option value="macos">macOS</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
      <p className="text-sm">{selected.length} / 25 ausdrücklich ausgewählte Katalogversionen. Ein Plattformwechsel verwirft die Auswahl.</p>
      {!rows.length && <p>Keine Katalogversionen verfügbar. Keine Beispieldaten.</p>}
      <ul className="space-y-3">{rows.map(row => <li key={row.id}>
        <label className="flex gap-3 items-start"><input type="checkbox" checked={selected.includes(row.id)} disabled={!selected.includes(row.id) && selected.length >= 25} onChange={event => {
          invalidate(); setSelected(values => event.target.checked ? [...values, row.id] : values.filter(value => value !== row.id));
        }} /><span>{row.name} · Version {row.version} · {row.platform}<span className="block text-xs break-all">{row.id}</span></span></label>
      </li>)}</ul>
      <button type="button" disabled={busy || !selected.length} onClick={preview}>Vorschau berechnen</button>
      {busy && <p role="status">Leseberechtigungen und ausgewählte Versionen werden geprüft …</p>}{error && <p role="alert">{error}</p>}
      {result && <section aria-label="Bestätigte Auswahlvorschau" className="space-y-4">
        <h3 className="font-semibold">Momentaufnahme bestätigt · {result.platform} · {result.configurationCount} Quellkonfigurationen</h3>
        <p>Nur die ausgewählten aktuellen Versionen zum Abfragezeitpunkt; keine Bestätigung einer wirksamen Gerätekonfiguration. 0 Lizenzreservierungen.</p>
        <ul className="text-xs space-y-2">{result.blueprints.map(row => <li className="break-all" key={row.id}>{row.name} · Version {row.version} · {row.platform} · {row.id}</li>)}</ul>
        {result.hasConflicts ? <p role="status">Konflikte in {result.conflicts.length} Konfigurationsarten. Keine automatische Auflösung.</p> : <p role="status">Keine Konflikte innerhalb dieser Auswahl. Keine Aussage über weitere Zuweisungen.</p>}
        <section aria-label="Nicht widersprüchliche Konfigurationsarten" className="space-y-3"><h4>Nicht widersprüchliche Konfigurationsarten</h4>
          {!result.effectiveConfigurations.length && <p>Keine nicht widersprüchlichen Konfigurationsarten in dieser Auswahl.</p>}
          {result.effectiveConfigurations.map(configuration => <article key={configuration.configType} className="rounded border border-white/15 p-3 space-y-2"><h5>{configuration.configType}</h5><Payload variant={configuration} blueprints={result.blueprints} /></article>)}
        </section>
        <section aria-label="Konflikte der Auswahl" className="space-y-3"><h4>Konflikte der Auswahl</h4>
          {result.conflicts.map(conflict => <article key={conflict.configType} className="rounded border border-amber-400/40 p-3 space-y-3"><h5>{conflict.configType} · {conflict.variants.length} abweichende vollständige Profile</h5>
            {conflict.variants.map((variant, index) => <div key={index} className="space-y-2"><h6>Variante {index + 1}</h6><Payload variant={variant} blueprints={result.blueprints} /></div>)}
          </article>)}
        </section>
      </section>}
    </div>}
  </section>;
}
