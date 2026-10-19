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
  blue:   { text: '#0071E3', bg: '#EAF4FF', iconColor: '#0071E3' },
  green:  { text: '#1c7c2e', bg: '#e8f8eb', iconColor: '#1c7c2e' },
  red:    { text: '#c0392b', bg: '#fdecea', iconColor: '#c0392b' },
  orange: { text: '#b34700', bg: '#fff0e6', iconColor: '#b34700' },
  purple: { text: '#6441a5', bg: '#f0ebf8', iconColor: '#6441a5' },
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
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--apple-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {card.label}
              </span>
              {card.icon && (
                <div style={{ width: 28, height: 28, borderRadius: 6, background: colors.bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <card.icon style={{ width: 16, height: 16, color: colors.iconColor }} />
                </div>
              )}
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--apple-text-primary)', lineHeight: 1 }}>
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
