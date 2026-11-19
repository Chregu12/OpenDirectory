'use client';

import React, { useState } from 'react';

function durationLabel(seconds: number) {
  if (seconds % 3600 === 0) return `${seconds / 3600} ${seconds === 3600 ? 'Stunde' : 'Stunden'}`;
  if (seconds % 60 === 0) return `${seconds / 60} ${seconds === 60 ? 'Minute' : 'Minuten'}`;
  return `${Math.floor(seconds / 60)} Min. ${seconds % 60} Sek.`;
}

export default function PIMDurationField({ seconds, maximumSeconds, onChange, disabled }: {
  seconds: number; maximumSeconds: number; onChange: (seconds: number) => void; disabled?: boolean;
}) {
  const [custom, setCustom] = useState(false);
  const maximum = Math.floor(maximumSeconds);
  const choices = Array.from(new Set([900, 3600, 14400, 36000, maximum])).filter(value => value >= 60 && value <= maximum).sort((a, b) => a - b);
  const individual = custom || !choices.includes(seconds);
  return <fieldset disabled={disabled} className="space-y-3">
    <label className="block">Gewünschte Dauer<select className="fluent-input block w-full" value={individual ? 'custom' : String(seconds)} onChange={event => {
      setCustom(event.target.value === 'custom'); if (event.target.value !== 'custom') onChange(Number(event.target.value));
    }}>{choices.map(value => <option key={value} value={value}>{durationLabel(value)}</option>)}<option value="custom">Andere Dauer …</option></select></label>
    {individual && <label className="block">Dauer (Minuten)<input className="fluent-input block w-full" type="number" min={1} max={maximum / 60} step="any" value={seconds / 60} onChange={event => onChange(Math.round(Number(event.target.value) * 60))} /></label>}
    <p className="text-sm">Maximal {durationLabel(maximum)}.</p>
  </fieldset>;
}
