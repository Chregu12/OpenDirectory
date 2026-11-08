'use client';
import React, { useMemo, useState } from 'react';
import { ChevronUpIcon, ChevronDownIcon } from '@heroicons/react/24/outline';

export interface Column<T> {
  key: keyof T | string;
  header: string;
  width?: number | string;
  sortable?: boolean;
  render?: (row: T, index: number) => React.ReactNode;
}
type Sort = { key: string; direction: 'asc' | 'desc' };
interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  getRowLabel?: (row: T) => string;
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
  onRowClick?: (row: T) => void;
  activeRowId?: string;
  emptyMessage?: string;
  loading?: boolean;
  label?: string;
  sort?: Sort;
  onSortChange?: (sort: Sort) => void;
}

export function DataTable<T>({ columns, rows, getRowId, getRowLabel = getRowId, selectedIds = new Set(), onSelectionChange,
  onRowClick, activeRowId, emptyMessage = 'Keine Einträge gefunden.', loading = false, label = 'Einträge', sort, onSortChange }: DataTableProps<T>) {
  const [localSort, setLocalSort] = useState<Sort | undefined>();
  const currentSort = onSortChange ? sort : localSort;
  const handleSort = (key: string) => {
    const next: Sort = { key, direction: currentSort?.key === key && currentSort.direction === 'asc' ? 'desc' : 'asc' };
    if (onSortChange) onSortChange(next); else setLocalSort(next);
  };
  const sortedRows = useMemo(() => {
    if (!currentSort || onSortChange) return rows;
    return [...rows].sort((a, b) => {
      const av = (a as Record<string, unknown>)[currentSort.key]; const bv = (b as Record<string, unknown>)[currentSort.key];
      const comparison = String(av ?? '').localeCompare(String(bv ?? ''), 'de', { numeric: true });
      return currentSort.direction === 'asc' ? comparison : -comparison;
    });
  }, [rows, currentSort, onSortChange]);
  const allSelected = rows.length > 0 && rows.every(row => selectedIds.has(getRowId(row)));
  const someSelected = rows.some(row => selectedIds.has(getRowId(row)));
  const toggleAll = () => {
    const next = new Set(selectedIds);
    rows.forEach(row => { if (allSelected) next.delete(getRowId(row)); else next.add(getRowId(row)); });
    onSelectionChange?.(next);
  };
  const toggleRow = (id: string) => {
    const next = new Set(selectedIds); if (next.has(id)) next.delete(id); else next.add(id);
    onSelectionChange?.(next);
  };
  return <div className="od-table-scroll" role="region" aria-label={label} tabIndex={0} aria-busy={loading}>
    {loading && <p role="status" className="p-4">Einträge werden geladen …</p>}
    <table className="fluent-table">
      <caption className="sr-only">{label}{columns.some(column => column.sortable) && !onSortChange ? ' · Sortierung nur der angezeigten Einträge' : ''}</caption>
      <thead><tr>
        {onSelectionChange && <th scope="col" style={{ width: 48 }}><label className="od-checkbox-target"><span className="sr-only">Alle angezeigten Einträge auswählen</span>
          <input type="checkbox" checked={allSelected} disabled={loading || !rows.length} ref={element => { if (element) element.indeterminate = !allSelected && someSelected; }} onChange={toggleAll} />
        </label></th>}
        {columns.map(column => <th key={String(column.key)} scope="col" style={{ width: column.width }}
          aria-sort={column.sortable ? currentSort?.key === String(column.key) ? currentSort.direction === 'asc' ? 'ascending' : 'descending' : 'none' : undefined}>
          {column.sortable ? <button type="button" className="od-sort-button" onClick={() => handleSort(String(column.key))} disabled={loading}
            title={!onSortChange ? 'Angezeigte Einträge sortieren' : undefined}>
            {column.header}{currentSort?.key === String(column.key) && currentSort.direction === 'desc' ? <ChevronDownIcon className="h-4 w-4" aria-hidden="true" /> : <ChevronUpIcon className="h-4 w-4" aria-hidden="true" />}
          </button> : column.header}
        </th>)}
        {onRowClick && <th scope="col"><span className="sr-only">Details</span></th>}
      </tr></thead>
      <tbody>{!sortedRows.length ? <tr><td colSpan={columns.length + Number(!!onSelectionChange) + Number(!!onRowClick)} className="text-center p-8">{loading ? 'Wird geladen …' : emptyMessage}</td></tr> : sortedRows.map((row, index) => {
        const id = getRowId(row); const rowLabel = getRowLabel(row);
        return <tr key={id} className={selectedIds.has(id) ? 'selected' : ''} data-active={activeRowId === id || undefined}
          onClick={event => { if (!(event.target as Element).closest('button, a, input, select, textarea, label')) onRowClick?.(row); }} style={{ cursor: onRowClick ? 'pointer' : undefined }}>
          {onSelectionChange && <td><label className="od-checkbox-target"><span className="sr-only">{rowLabel} auswählen</span>
            <input type="checkbox" checked={selectedIds.has(id)} onChange={() => toggleRow(id)} />
          </label></td>}
          {columns.map(column => <td key={String(column.key)}>{column.render ? column.render(row, index) : String((row as Record<string, unknown>)[String(column.key)] ?? '')}</td>)}
          {onRowClick && <td><button type="button" className="fluent-btn-ghost" aria-label={'Details für ' + rowLabel} onClick={() => onRowClick(row)}>Öffnen</button></td>}
        </tr>;
      })}</tbody>
    </table>
    {columns.some(column => column.sortable) && !onSortChange && <p className="px-4 py-2 text-sm" style={{ color: 'var(--text-secondary)' }}>Sortierung der angezeigten Einträge.</p>}
  </div>;
}
