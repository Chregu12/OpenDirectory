'use client';
import React, { useState } from 'react';
import { DetailPanel } from '@/components/ui/DetailPanel';
import { Device, DeviceInput, deviceClasses, devicePlatforms, normalizeDeviceInput } from '@/lib/deviceInventory';

export const deviceClassLabels = { smartphone: 'Smartphone', tablet: 'Tablet', laptop: 'Laptop', desktop: 'Desktop', shared: 'Gemeinschaftsgerät', kiosk: 'Kiosk', other: 'Sonstiges' };
export const devicePlatformLabels = { macos: 'macOS', ios: 'iOS', ipados: 'iPadOS', windows: 'Windows', linux: 'Linux', android: 'Android', other: 'Sonstiges' };
export const deviceOwnershipLabels = { corporate: 'Unternehmen', byod: 'Privatgerät (BYOD)', shared: 'Gemeinsame Nutzung' };
export const deviceLifecycleLabels = { available: 'Verfügbar', assigned: 'Zugewiesen', maintenance: 'In Wartung', retired: 'Archiviert' };
const empty: DeviceInput = { assetId: '', serialNumber: '', manufacturer: '', model: '', deviceClass: 'laptop', platform: 'other', osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '' };

export default function DeviceInventoryEditor({ device, busy, onClose, onSave }: { device: Device | null; busy: boolean; onClose: () => void; onSave: (values: DeviceInput, reason: string) => Promise<void> }) {
  const [values, setValues] = useState<DeviceInput>(() => device ? Object.fromEntries(Object.keys(empty).map(field => [field, device[field]])) as DeviceInput : { ...empty });
  const [reason, setReason] = useState(''); const [error, setError] = useState('');
  return <DetailPanel open title={device ? 'Stammdaten bearbeiten' : 'Gerät erfassen'} subtitle={device ? `${device.assetId} · Version ${device.revision}` : 'Neues Gerät im Firmeninventar'} width={640} onClose={() => { if (!busy) onClose(); }}>
    <form className="space-y-5" onSubmit={async event => {
      event.preventDefault(); if (busy) return; setError('');
      let normalized: DeviceInput;
      try { normalized = normalizeDeviceInput(values); } catch { setError('Bitte Pflichtfelder, Datumswerte und Garantiezeitraum prüfen.'); return; }
      if (device && Object.entries(normalized).every(([field, value]) => device[field] === value)) { setError('Keine Stammdaten geändert.'); return; }
      if (device && (reason.trim().length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(reason))) { setError('Bitte eine einzeilige Begründung mit 10–500 Zeichen eingeben.'); return; }
      await onSave(normalized, reason.trim());
    }}>
      <p className="text-sm text-[var(--text-secondary)]">{device ? 'Zuweisung und Gerätehistorie bleiben erhalten.' : 'Der neue Eintrag ist verfügbar und keinem Benutzer zugewiesen.'}</p>
      <fieldset disabled={busy} className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {([{ field: 'assetId', label: 'Inventarnummer' }, { field: 'serialNumber', label: 'Seriennummer' }, { field: 'manufacturer', label: 'Hersteller' }, { field: 'model', label: 'Modell' }, { field: 'osVersion', label: 'Betriebssystemversion' }] as const).map(({ field, label }) => <label key={field} className="text-sm">{label}<input className="input-apple block" name={field} required={field !== 'osVersion'} maxLength={120} value={values[field]} onChange={event => setValues(previous => ({ ...previous, [field]: event.target.value }))} /></label>)}
        <label className="text-sm">Geräteklasse<select className="input-apple block" value={values.deviceClass} onChange={event => setValues(previous => ({ ...previous, deviceClass: event.target.value as DeviceInput['deviceClass'] }))}>{deviceClasses.map(value => <option key={value} value={value}>{deviceClassLabels[value]}</option>)}</select></label>
        <label className="text-sm">Plattform<select className="input-apple block" value={values.platform} onChange={event => setValues(previous => ({ ...previous, platform: event.target.value as DeviceInput['platform'] }))}>{devicePlatforms.map(value => <option key={value} value={value}>{devicePlatformLabels[value]}</option>)}</select></label>
        <label className="text-sm">Eigentum<select className="input-apple block" value={values.ownership} onChange={event => setValues(previous => ({ ...previous, ownership: event.target.value as DeviceInput['ownership'] }))}>{Object.entries(deviceOwnershipLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        {([{ field: 'purchaseDate', label: 'Kaufdatum' }, { field: 'warrantyEnd', label: 'Garantieende' }] as const).map(({ field, label }) => <label className="text-sm" key={field}>{label}<input className="input-apple block" type="date" value={values[field]} onChange={event => setValues(previous => ({ ...previous, [field]: event.target.value }))} /></label>)}
        <label className="text-sm md:col-span-2">Beschreibung<input className="input-apple block" maxLength={2000} value={values.description} onChange={event => setValues(previous => ({ ...previous, description: event.target.value }))} /></label>
        {device && <label className="text-sm md:col-span-2">Änderungsbegründung<input className="input-apple block" required minLength={10} maxLength={500} value={reason} onChange={event => setReason(event.target.value)} /></label>}
      </fieldset>
      {error && <p role="alert">{error}</p>}
      <div className="flex justify-end gap-3 border-t border-[var(--border)] pt-4"><button className="fluent-btn-secondary" type="button" disabled={busy} onClick={onClose}>Abbrechen</button><button className="fluent-btn-primary" disabled={busy}>{busy ? 'Wird gespeichert …' : device ? 'Änderungen speichern' : 'Im Inventar speichern'}</button></div>
    </form>
  </DetailPanel>;
}
