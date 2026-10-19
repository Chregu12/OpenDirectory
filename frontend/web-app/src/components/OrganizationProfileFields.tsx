'use client';

import React from 'react';
import { FIELDS, OrganizationProfile } from '../../../../packages/organization-profile-contract';

const groups: { title: string; fields: (keyof OrganizationProfile)[] }[] = [
  { title: 'Unternehmen', fields: ['name', 'legalForm', 'registrationNumber', 'taxId'] },
  { title: 'Geschäftsadresse', fields: ['addressLine1', 'addressLine2', 'postalCode', 'city', 'country'] },
  { title: 'Kontakt', fields: ['contactEmail', 'contactPhone', 'website'] },
  { title: 'Einstellungen', fields: ['timezone', 'defaultLanguage'] },
];
const labels: Record<keyof OrganizationProfile, string> = {
  name: 'Firmenname', legalForm: 'Rechtsform', registrationNumber: 'Registrierungsnummer', taxId: 'UID / Steuer-ID', addressLine1: 'Strasse und Hausnummer', addressLine2: 'Adresszusatz',
  postalCode: 'Postleitzahl', city: 'Ort', country: 'Land (zweistellig, z. B. CH)', timezone: 'Zeitzone (z. B. Europe/Zurich)', defaultLanguage: 'Standardsprache', contactEmail: 'Kontakt-E-Mail', contactPhone: 'Telefon', website: 'Website (HTTPS)',
};
const required = ['name', 'addressLine1', 'postalCode', 'city', 'country', 'timezone', 'defaultLanguage', 'contactEmail'];

export default function OrganizationProfileFields({ value, onChange, disabled, prefix = 'organization' }: {
  value: OrganizationProfile; onChange: (profile: OrganizationProfile) => void; disabled: boolean; prefix?: string;
}) {
  return <>{groups.map(group => <fieldset key={group.title} disabled={disabled} className="border rounded-xl p-5">
    <legend className="px-2 font-semibold">{group.title}</legend><div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {group.fields.map(field => <label key={field} htmlFor={`${prefix}-${field}`} className="space-y-1"><span className="block text-sm">{labels[field]}{required.includes(field) ? ' *' : ''}</span>
        {field === 'defaultLanguage' ? <select id={`${prefix}-${field}`} className="w-full border rounded px-3 py-2 bg-transparent" value={value[field]} onChange={event => onChange({ ...value, [field]: event.target.value })}><option value="de">Deutsch</option><option value="en">English</option></select>
          : <input id={`${prefix}-${field}`} className="w-full border rounded px-3 py-2 bg-transparent" value={value[field]} maxLength={FIELDS[field]} required={required.includes(field)}
            type={field === 'contactEmail' ? 'email' : field === 'website' ? 'url' : field === 'contactPhone' ? 'tel' : 'text'} onChange={event => onChange({ ...value, [field]: field === 'country' ? event.target.value.toUpperCase() : event.target.value })} />}
      </label>)}
    </div>
  </fieldset>)}</>;
}
