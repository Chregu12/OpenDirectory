'use client';

import React, { useEffect, useState } from 'react';
import { calculateRam, MODULES, CORE_RAM_MB } from '@/lib/modules';


interface RamMeterProps {
  /** Currently enabled module IDs */
  enabledModules: string[];
  /** System total RAM in MB (auto-detected if not provided) */
  systemRamMB?: number;
  /** Compact mode for inline display */
  compact?: boolean;
  /** Show per-module breakdown */
  showBreakdown?: boolean;
}

const CATEGORY_COLORS: Record<string, { bg: string; bar: string; text: string }> = {
  core: { bg: 'bg-blue-100', bar: 'bg-blue-500', text: 'text-blue-700' },
  infrastructure: { bg: 'bg-green-100', bar: 'bg-green-500', text: 'text-green-700' },
  monitoring: { bg: 'bg-purple-100', bar: 'bg-purple-500', text: 'text-purple-700' },
  security: { bg: 'bg-orange-100', bar: 'bg-orange-500', text: 'text-orange-700' },
  enterprise: { bg: 'bg-cyan-100', bar: 'bg-cyan-500', text: 'text-cyan-700' },
};

export default function RamMeter({
  enabledModules,
  systemRamMB: propSystemRam,
  compact = false,
  showBreakdown = true,
}: RamMeterProps) {
  const [systemRamMB, setSystemRamMB] = useState(propSystemRam || 0);
  const ram = calculateRam(enabledModules);

  useEffect(() => {
    if (!propSystemRam) setSystemRamMB(4096);
  }, [propSystemRam]);

  const usagePercent = systemRamMB > 0 ? Math.min(100, (ram.totalMB / systemRamMB) * 100) : 0;
  const isWarning = usagePercent > 75;
  const isCritical = usagePercent > 90;

  // Compact mode: just the bar and number
  if (compact) {
    return (
      <div className="flex items-center space-x-3">
        <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              isCritical ? 'bg-red-500' : isWarning ? 'bg-yellow-500' : 'bg-blue-500'
            }`}
            style={{ width: `${Math.max(5, (ram.totalMB / Math.max(systemRamMB, ram.totalMB + 512)) * 100)}%` }}
          />
        </div>
        <span className={`text-sm font-mono font-medium ${
          isCritical ? 'text-red-600' : isWarning ? 'text-yellow-600' : 'text-gray-700'
        }`}>
          ~{ram.totalGB} GB
        </span>
      </div>
    );
  }

  // Build segmented bar data
  const segments = [
    { label: 'Kern', mb: CORE_RAM_MB, color: 'bg-blue-500' },
    ...enabledModules.map(id => {
      const mod = MODULES.find(m => m.id === id);
      if (!mod) return null;
      const cat = CATEGORY_COLORS[mod.category] || CATEGORY_COLORS.core;
      return { label: mod.name, mb: mod.ramMB, color: cat.bar };
    }).filter(Boolean) as { label: string; mb: number; color: string }[],
  ];
  const maxBar = Math.max(systemRamMB, ram.totalMB + 512);

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">RAM-Verbrauch</h3>
          <p className="text-xs text-gray-500">
            Geschätzt basierend auf aktiven Modulen
          </p>
        </div>
        <div className="text-right">
          <span className={`text-2xl font-bold ${
            isCritical ? 'text-red-600' : isWarning ? 'text-yellow-600' : 'text-gray-900'
          }`}>
            ~{ram.totalGB}
          </span>
          <span className="text-sm text-gray-500 ml-1">GB</span>
          {systemRamMB > 0 && (
            <p className="text-xs text-gray-400">
              von {(systemRamMB / 1024).toFixed(0)} GB System
            </p>
          )}
        </div>
      </div>

      {/* Segmented bar */}
      <div className="h-4 bg-gray-100 rounded-full overflow-hidden flex mb-2">
        {segments.map((seg, i) => (
          <div
            key={i}
            className={`${seg.color} transition-all duration-500 ${i === 0 ? 'rounded-l-full' : ''} ${
              i === segments.length - 1 ? 'rounded-r-full' : ''
            }`}
            style={{ width: `${(seg.mb / maxBar) * 100}%` }}
            title={`${seg.label}: ${seg.mb} MB`}
          />
        ))}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 mb-4">
        {segments.map((seg, i) => (
          <div key={i} className="flex items-center text-xs text-gray-600">
            <div className={`w-2.5 h-2.5 rounded-sm ${seg.color} mr-1.5`} />
            <span>{seg.label}</span>
            <span className="text-gray-400 ml-1">{seg.mb} MB</span>
          </div>
        ))}
      </div>

      {/* Warning */}
      {isCritical && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-sm text-red-700 mb-3">
          RAM-Verbrauch über 90% — deaktiviere Module oder rüste RAM auf.
        </div>
      )}
      {isWarning && !isCritical && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg px-3 py-2 text-sm text-yellow-700 mb-3">
          RAM-Verbrauch über 75% — behalte die Systemleistung im Auge.
        </div>
      )}

      {/* Breakdown table */}
      {showBreakdown && (
        <details className="group">
          <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-700 select-none">
            Detail-Aufschlüsselung anzeigen
          </summary>
          <div className="mt-2 space-y-1">
            {ram.breakdown.map((item, i) => (
              <div key={i} className="flex items-center justify-between text-xs py-1 border-b border-gray-50 last:border-0">
                <div className="flex items-center">
                  <span className={`w-1.5 h-1.5 rounded-full mr-2 ${
                    item.type === 'core' ? 'bg-blue-500' : 'bg-green-500'
                  }`} />
                  <span className="text-gray-700">{item.name}</span>
                  <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] ${
                    item.type === 'core' ? 'bg-blue-50 text-blue-600' : 'bg-green-50 text-green-600'
                  }`}>
                    {item.type === 'core' ? 'Kern' : 'Modul'}
                  </span>
                </div>
                <span className="text-gray-500 font-mono">{item.ramMB} MB</span>
              </div>
            ))}
            <div className="flex items-center justify-between text-xs font-medium pt-2 border-t border-gray-200">
              <span className="text-gray-900">Gesamt</span>
              <span className="text-gray-900 font-mono">{ram.totalMB} MB (~{ram.totalGB} GB)</span>
            </div>
          </div>
        </details>
      )}
    </div>
  );
}
