'use client';
import React, { useState } from 'react';
import { ChevronUpIcon, ChevronDownIcon } from '@heroicons/react/24/outline';

export interface Column<T> {
  key: keyof T | string;
  header: string;
  width?: number | string;
  sortable?: boolean;
  render?: (row: T, index: number) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
  onRowClick?: (row: T) => void;
  activeRowId?: string;
  emptyMessage?: string;
  loading?: boolean;
}

export function DataTable<T>({
  columns,
  rows,
  getRowId,
  selectedIds,
  onSelectionChange,
  onRowClick,
  activeRowId,
  emptyMessage = 'No items found.',
  loading = false,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const sortedRows = React.useMemo(() => {
    if (!sortKey) return rows;
    return [...rows].sort((a, b) => {
      const av = (a as Record<string, unknown>)[sortKey];
      const bv = (b as Record<string, unknown>)[sortKey];
      const cmp = String(av ?? '').localeCompare(String(bv ?? ''), undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [rows, sortKey, sortDir]);

  const allSelected = rows.length > 0 && selectedIds && rows.every(r => selectedIds.has(getRowId(r)));
  const someSelected = selectedIds && rows.some(r => selectedIds.has(getRowId(r)));

  const toggleAll = () => {
    if (!onSelectionChange) return;
    if (allSelected) {
      onSelectionChange(new Set());
    } else {
      onSelectionChange(new Set(rows.map(getRowId)));
    }
  };

  const toggleRow = (id: string) => {
    if (!onSelectionChange || !selectedIds) return;
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelectionChange(next);
  };

  if (loading) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Loading…
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="fluent-table">
        <thead>
          <tr>
            {onSelectionChange && (
              <th style={{ width: 40 }}>
                <input
                  type="checkbox"
                  checked={!!allSelected}
                  ref={el => { if (el) el.indeterminate = !allSelected && !!someSelected; }}
                  onChange={toggleAll}
                  style={{ cursor: 'pointer' }}
                />
              </th>
            )}
            {columns.map(col => (
              <th
                key={String(col.key)}
                style={{ width: col.width }}
                onClick={() => col.sortable && handleSort(String(col.key))}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  {col.header}
                  {col.sortable && sortKey === String(col.key) && (
                    sortDir === 'asc'
                      ? <ChevronUpIcon style={{ width: 12, height: 12 }} />
                      : <ChevronDownIcon style={{ width: 12, height: 12 }} />
                  )}
                  {col.sortable && sortKey !== String(col.key) && (
                    <span style={{ opacity: 0.3 }}><ChevronUpIcon style={{ width: 12, height: 12 }} /></span>
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length + (onSelectionChange ? 1 : 0)} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-secondary)' }}>
                {emptyMessage}
              </td>
            </tr>
          ) : (
            sortedRows.map((row, i) => {
              const id = getRowId(row);
              const isActive = activeRowId === id;
              const isSelected = !!selectedIds?.has(id);
              return (
                <tr
                  key={id}
                  className={isSelected ? 'selected' : ''}
                  onClick={() => onRowClick?.(row)}
                  style={{
                    cursor: onRowClick ? 'pointer' : 'default',
                    outline: isActive ? '2px solid var(--accent-blue)' : 'none',
                    outlineOffset: -1,
                  }}
                >
                  {onSelectionChange && (
                    <td onClick={e => { e.stopPropagation(); toggleRow(id); }}>
                      <input type="checkbox" checked={isSelected} onChange={() => {}} style={{ cursor: 'pointer' }} />
                    </td>
                  )}
                  {columns.map(col => (
                    <td key={String(col.key)}>
                      {col.render
                        ? col.render(row, i)
                        : String((row as Record<string, unknown>)[String(col.key)] ?? '')}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
