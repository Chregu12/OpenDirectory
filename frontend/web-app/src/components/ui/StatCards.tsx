'use client';
import React from 'react';

export interface StatCard {
  label: string;
  value: number | string;
  icon?: React.FC<React.SVGProps<SVGSVGElement>>;
  trend?: { value: number; direction: 'up' | 'down' | 'neutral' };
  color?: 'blue' | 'green' | 'red' | 'orange' | 'purple';
  onClick?: () => void;
}

const colorMap: Record<string, { text: string; bg: string; iconColor: string }> = {
  blue:   { text: 'var(--ms-blue, #0078d4)',   bg: 'var(--ms-blue-light, #eff6fc)',   iconColor: 'var(--ms-blue, #0078d4)' },
  green:  { text: 'var(--success, #107c10)',    bg: 'var(--success-light, #dff6dd)',   iconColor: 'var(--success, #107c10)' },
  red:    { text: 'var(--danger, #a4262c)',     bg: 'var(--danger-light, #fde7e9)',    iconColor: 'var(--danger, #a4262c)' },
  orange: { text: 'var(--warning, #d83b01)',    bg: 'var(--warning-light, #fed9cc)',   iconColor: 'var(--warning, #d83b01)' },
  purple: { text: 'var(--ms-purple, #7c4fba)', bg: 'var(--ms-purple-light, #f4eefb)', iconColor: 'var(--ms-purple, #7c4fba)' },
};

export function StatCards({ cards }: { cards: StatCard[] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(cards.length, 4)}, 1fr)`, gap: 12, marginBottom: 20 }}>
      {cards.map((card, i) => {
        const colors = colorMap[card.color || 'blue'];
        return (
          <div
            key={i}
            className="fluent-stat-card"
            onClick={card.onClick}
            style={{ cursor: card.onClick ? 'pointer' : 'default' }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {card.label}
              </span>
              {card.icon && (
                <div style={{ width: 28, height: 28, borderRadius: 6, background: colors.bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <card.icon style={{ width: 16, height: 16, color: colors.iconColor }} />
                </div>
              )}
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
              {card.value.toLocaleString()}
            </div>
            {card.trend && (
              <div style={{ marginTop: 4, fontSize: 12, color: card.trend.direction === 'up' ? 'var(--success)' : card.trend.direction === 'down' ? 'var(--danger)' : 'var(--text-secondary)' }}>
                {card.trend.direction === 'up' ? '↑' : card.trend.direction === 'down' ? '↓' : '→'} {Math.abs(card.trend.value)}%
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
