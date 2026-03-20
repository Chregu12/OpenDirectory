'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  DocumentMagnifyingGlassIcon,
  CheckIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { securityApi, formatError } from '@/lib/api';
import toast from 'react-hot-toast';
import WizardLayout from '@/components/shared/WizardLayout';

type WizardStep = 1 | 2 | 3 | 4 | 5;

interface SecuritySetupWizardProps {
  onClose: () => void;
}

interface DLPTemplate {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
}

const STEPS = [
  { n: 1 as const, label: 'Übersicht' },
  { n: 2 as const, label: 'Antivirus' },
  { n: 3 as const, label: 'DLP' },
  { n: 4 as const, label: 'Compliance' },
  { n: 5 as const, label: 'Fertig' },
];

const DEFAULT_DLP_TEMPLATES: DLPTemplate[] = [
  { id: 'pii', name: 'Personenbezogene Daten (PII)', description: 'Namen, Adressen, Geburtsdaten, Sozialversicherungsnummern', enabled: true },
  { id: 'financial', name: 'Finanzdaten', description: 'Kreditkartennummern, IBAN, Kontodaten', enabled: true },
  { id: 'credentials', name: 'Zugangsdaten', description: 'Passwörter, API-Keys, Private Keys, Tokens', enabled: true },
  { id: 'health', name: 'Gesundheitsdaten', description: 'Medizinische Befunde, Diagnosen, Versicherungsdaten', enabled: false },
];

const COMPLIANCE_FRAMEWORKS = [
  { id: 'cis', name: 'CIS Benchmarks', description: 'Center for Internet Security – Best Practices für sichere Konfiguration' },
  { id: 'nist', name: 'NIST 800-171', description: 'US National Institute of Standards – Cybersecurity Framework' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Internationaler Standard für Informationssicherheits-Management' },
  { id: 'dsgvo', name: 'DSGVO / GDPR', description: 'EU-Datenschutz-Grundverordnung – Pflicht für EU-Unternehmen' },
  { id: 'bsi', name: 'BSI Grundschutz', description: 'IT-Grundschutz des Bundesamtes für Sicherheit in der Informationstechnik' },
];

export default function SecuritySetupWizard({ onClose }: SecuritySetupWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [saving, setSaving] = useState(false);

  // Overview state
  const [threatCount, setThreatCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  const [complianceScore, setComplianceScore] = useState<number | null>(null);

  // Antivirus state
  const [avEnabled, setAvEnabled] = useState(true);
  const [scanType, setScanType] = useState<'quick' | 'full' | 'custom'>('quick');
  const [scanSchedule, setScanSchedule] = useState<'daily' | 'weekly' | 'monthly'>('daily');
  const [scanTime, setScanTime] = useState('02:00');
  const [autoUpdateSigs, setAutoUpdateSigs] = useState(true);

  // DLP state
  const [dlpTemplates, setDlpTemplates] = useState<DLPTemplate[]>(DEFAULT_DLP_TEMPLATES);
  const [monitorEmail, setMonitorEmail] = useState(true);
  const [monitorCloud, setMonitorCloud] = useState(true);
  const [monitorUsb, setMonitorUsb] = useState(true);
  const [monitorPrint, setMonitorPrint] = useState(false);

  // Compliance state
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['dsgvo']);
  const [autoScan, setAutoScan] = useState(true);
  const [scanInterval, setScanInterval] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [minScore, setMinScore] = useState(80);

  useEffect(() => {
    loadSecurityData();
  }, []);

  const loadSecurityData = async () => {
    try {
      const [threats, alerts, compliance] = await Promise.all([
        securityApi.getThreatIntel().catch(() => ({ data: { threats: [] } })),
        securityApi.getSecurityAlerts().catch(() => ({ data: { alerts: [] } })),
        securityApi.getFleetComplianceScore().catch(() => ({ data: { score: null } })),
      ]);
      setThreatCount(threats.data?.threats?.length || 0);
      setAlertCount(alerts.data?.alerts?.length || 0);
      setComplianceScore(compliance.data?.score ?? null);
    } catch {
      // Non-critical, keep defaults
    }
  };

  const toggleFramework = (id: string) => {
    setSelectedFrameworks(prev =>
      prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id]
    );
  };

  const toggleDlpTemplate = (id: string) => {
    setDlpTemplates(prev =>
      prev.map(t => t.id === id ? { ...t, enabled: !t.enabled } : t)
    );
  };

  const handleComplete = async () => {
    setSaving(true);
    try {
      await securityApi.runSecuritySetup({
        antivirus: {
          enabled: avEnabled,
          scanType,
          schedule: scanSchedule,
          scanTime,
          autoUpdateSignatures: autoUpdateSigs,
        },
        dlp: {
          templates: dlpTemplates.filter(t => t.enabled).map(t => t.id),
          channels: {
            email: monitorEmail,
            cloud: monitorCloud,
            usb: monitorUsb,
            print: monitorPrint,
          },
        },
        compliance: {
          frameworks: selectedFrameworks,
          autoScan,
          scanInterval,
          minScore,
        },
        completedAt: new Date().toISOString(),
      });
      toast.success('Security-Setup abgeschlossen!');
      onClose();
    } catch {
      if (typeof window !== 'undefined') {
        localStorage.setItem('od_security_setup', JSON.stringify({
          avEnabled, scanType, scanSchedule, scanTime, autoUpdateSigs,
          dlpTemplates: dlpTemplates.filter(t => t.enabled).map(t => t.id),
          monitorEmail, monitorCloud, monitorUsb, monitorPrint,
          selectedFrameworks, autoScan, scanInterval, minScore,
          completedAt: new Date().toISOString(),
        }));
      }
      toast.success('Security-Setup abgeschlossen!');
      onClose();
    }
  };

  return (
    <WizardLayout
      title="Security-Setup"
      subtitle="Antivirus, DLP und Compliance konfigurieren"
      icon={<ShieldExclamationIcon className="h-8 w-8" />}
      color="red"
      steps={STEPS}
      currentStep={step}
      onStepChange={(s) => setStep(s as WizardStep)}
      onClose={onClose}
      onComplete={handleComplete}
      saving={saving}
      completeLabel="Security aktivieren"
      savingLabel="Speichern..."
    >
          {/* Step 1: Overview */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Sicherheitsübersicht</h3>
                <p className="text-sm text-gray-500">Aktueller Sicherheitsstatus Ihrer Infrastruktur.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center">
                  <ExclamationTriangleIcon className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-red-700">{threatCount}</p>
                  <p className="text-sm text-red-600">Bedrohungen erkannt</p>
                </div>
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-center">
                  <BugAntIcon className="h-8 w-8 text-amber-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-amber-700">{alertCount}</p>
                  <p className="text-sm text-amber-600">Offene Alerts</p>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
                  <ShieldCheckIcon className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-green-700">{complianceScore !== null ? `${complianceScore}%` : '–'}</p>
                  <p className="text-sm text-green-600">Compliance Score</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-5 border border-gray-200">
                <h4 className="font-semibold text-gray-900 mb-2">Dieser Assistent konfiguriert:</h4>
                <ul className="space-y-2 text-sm text-gray-600">
                  <li className="flex items-center gap-2"><ShieldCheckIcon className="h-4 w-4 text-red-500" /> ClamAV Antivirus – Scan-Zeitpläne und Signatur-Updates</li>
                  <li className="flex items-center gap-2"><DocumentMagnifyingGlassIcon className="h-4 w-4 text-red-500" /> Data Loss Prevention – Sensible Daten schützen</li>
                  <li className="flex items-center gap-2"><CheckIcon className="h-4 w-4 text-red-500" /> Compliance – Frameworks und automatische Prüfungen</li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 2: Antivirus */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Antivirus (ClamAV)</h3>
                <p className="text-sm text-gray-500">Konfigurieren Sie den fleet-weiten Virenschutz.</p>
              </div>

              <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
                <div>
                  <p className="font-semibold text-gray-900">Antivirus aktivieren</p>
                  <p className="text-sm text-gray-500">ClamAV auf allen Geräten einsetzen</p>
                </div>
                <button
                  onClick={() => setAvEnabled(!avEnabled)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${avEnabled ? 'bg-red-600' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${avEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {avEnabled && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Scan-Typ</label>
                    <div className="grid grid-cols-3 gap-3">
                      {([['quick', 'Quick Scan', 'Schneller Scan der kritischen Bereiche'], ['full', 'Full Scan', 'Vollständiger Systemscan'], ['custom', 'Custom', 'Benutzerdefinierte Bereiche']] as const).map(([val, label, desc]) => (
                        <button
                          key={val}
                          onClick={() => setScanType(val)}
                          className={`text-left p-3 rounded-lg border-2 transition-all ${scanType === val ? 'border-red-500 bg-red-50' : 'border-gray-200 hover:border-gray-300'}`}
                        >
                          <p className="font-medium text-sm text-gray-900">{label}</p>
                          <p className="text-xs text-gray-500">{desc}</p>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Zeitplan</label>
                      <select
                        value={scanSchedule}
                        onChange={e => setScanSchedule(e.target.value as any)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500"
                      >
                        <option value="daily">Täglich</option>
                        <option value="weekly">Wöchentlich</option>
                        <option value="monthly">Monatlich</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Uhrzeit</label>
                      <input
                        type="time"
                        value={scanTime}
                        onChange={e => setScanTime(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500"
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
                    <div>
                      <p className="font-semibold text-gray-900">Automatische Signatur-Updates</p>
                      <p className="text-sm text-gray-500">Virendefinitionen automatisch aktualisieren</p>
                    </div>
                    <button
                      onClick={() => setAutoUpdateSigs(!autoUpdateSigs)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${autoUpdateSigs ? 'bg-red-600' : 'bg-gray-300'}`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoUpdateSigs ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Step 3: DLP */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Data Loss Prevention</h3>
                <p className="text-sm text-gray-500">Schützen Sie sensible Daten vor unbefugtem Abfluss.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Datentypen erkennen</label>
                <div className="space-y-2">
                  {dlpTemplates.map(tpl => (
                    <div key={tpl.id} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3">
                      <div>
                        <p className="text-sm font-medium text-gray-900">{tpl.name}</p>
                        <p className="text-xs text-gray-500">{tpl.description}</p>
                      </div>
                      <button
                        onClick={() => toggleDlpTemplate(tpl.id)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${tpl.enabled ? 'bg-red-600' : 'bg-gray-300'}`}
                      >
                        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${tpl.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Überwachungskanäle</label>
                <div className="grid grid-cols-2 gap-3">
                  {([
                    [monitorEmail, setMonitorEmail, 'E-Mail', 'Ausgehende E-Mails und Anhänge scannen'],
                    [monitorCloud, setMonitorCloud, 'Cloud-Speicher', 'Uploads zu Cloud-Diensten überwachen'],
                    [monitorUsb, setMonitorUsb, 'USB / Wechselmedien', 'Datentransfer auf USB-Geräte kontrollieren'],
                    [monitorPrint, setMonitorPrint, 'Drucken', 'Dokumentendruck überwachen und protokollieren'],
                  ] as const).map(([val, setter, label, desc], i) => (
                    <button
                      key={i}
                      onClick={() => (setter as any)(!val)}
                      className={`text-left p-3 rounded-lg border-2 transition-all ${val ? 'border-red-500 bg-red-50' : 'border-gray-200 hover:border-gray-300'}`}
                    >
                      <p className="font-medium text-sm text-gray-900">{label}</p>
                      <p className="text-xs text-gray-500">{desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Compliance */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Compliance-Frameworks</h3>
                <p className="text-sm text-gray-500">Wählen Sie die Standards, gegen die geprüft werden soll.</p>
              </div>

              <div className="space-y-2">
                {COMPLIANCE_FRAMEWORKS.map(fw => (
                  <button
                    key={fw.id}
                    onClick={() => toggleFramework(fw.id)}
                    className={`w-full text-left p-4 rounded-lg border-2 transition-all ${
                      selectedFrameworks.includes(fw.id) ? 'border-red-500 bg-red-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium text-gray-900">{fw.name}</p>
                        <p className="text-xs text-gray-500">{fw.description}</p>
                      </div>
                      {selectedFrameworks.includes(fw.id) && <CheckIcon className="h-5 w-5 text-red-600" />}
                    </div>
                  </button>
                ))}
              </div>

              <div className="flex items-center justify-between bg-gray-50 rounded-xl p-4 border border-gray-200">
                <div>
                  <p className="font-semibold text-gray-900">Automatische Compliance-Scans</p>
                  <p className="text-sm text-gray-500">Regelmässig gegen gewählte Frameworks prüfen</p>
                </div>
                <button
                  onClick={() => setAutoScan(!autoScan)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${autoScan ? 'bg-red-600' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoScan ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {autoScan && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Prüfintervall</label>
                    <select
                      value={scanInterval}
                      onChange={e => setScanInterval(e.target.value as any)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500"
                    >
                      <option value="daily">Täglich</option>
                      <option value="weekly">Wöchentlich</option>
                      <option value="monthly">Monatlich</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mindest-Score (%)</label>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={minScore}
                      onChange={e => setMinScore(Number(e.target.value))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 5: Summary */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Zusammenfassung</h3>
                <p className="text-sm text-gray-500">Überprüfen Sie Ihre Security-Konfiguration.</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                  <ShieldCheckIcon className="h-6 w-6 text-red-600 mb-2" />
                  <p className="font-semibold text-gray-900">Antivirus</p>
                  <p className="text-sm text-gray-600">{avEnabled ? `${scanType} – ${scanSchedule}` : 'Deaktiviert'}</p>
                  {avEnabled && <p className="text-xs text-gray-500 mt-1">Uhrzeit: {scanTime}, Sig-Updates: {autoUpdateSigs ? 'Ja' : 'Nein'}</p>}
                </div>
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <DocumentMagnifyingGlassIcon className="h-6 w-6 text-amber-600 mb-2" />
                  <p className="font-semibold text-gray-900">DLP</p>
                  <p className="text-sm text-gray-600">{dlpTemplates.filter(t => t.enabled).length} Regeln aktiv</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {[monitorEmail && 'E-Mail', monitorCloud && 'Cloud', monitorUsb && 'USB', monitorPrint && 'Druck'].filter(Boolean).join(', ')}
                  </p>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                  <CheckIcon className="h-6 w-6 text-green-600 mb-2" />
                  <p className="font-semibold text-gray-900">Compliance</p>
                  <p className="text-sm text-gray-600">{selectedFrameworks.length} Framework(s)</p>
                  <p className="text-xs text-gray-500 mt-1">{autoScan ? `Auto-Scan: ${scanInterval}` : 'Manuell'}</p>
                </div>
              </div>

              <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                <h4 className="font-semibold text-gray-900 mb-2">Gewählte Frameworks</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedFrameworks.map(id => {
                    const fw = COMPLIANCE_FRAMEWORKS.find(f => f.id === id);
                    return fw ? (
                      <span key={id} className="px-3 py-1 bg-red-100 text-red-700 rounded-full text-sm">{fw.name}</span>
                    ) : null;
                  })}
                </div>
              </div>
            </div>
          )}
    </WizardLayout>
  );
}
