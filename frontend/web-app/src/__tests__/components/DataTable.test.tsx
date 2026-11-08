import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable } from '@/components/ui/DataTable';

const rows = [{ id: '1', name: 'Zürich' }, { id: '2', name: 'Bern' }];
const columns = [{ key: 'name', header: 'Name', sortable: true }];

test('sorts with the keyboard and exposes the direction', async () => {
  render(<DataTable columns={columns} rows={rows} getRowId={row => row.id} />);
  screen.getByRole('button', { name: 'Name' }).focus();
  await userEvent.keyboard('{Enter}');
  expect(screen.getByRole('columnheader', { name: 'Name' })).toHaveAttribute('aria-sort', 'ascending');
  expect(screen.getAllByRole('row')[1]).toHaveTextContent('Bern');
  await userEvent.keyboard(' ');
  expect(screen.getByRole('columnheader', { name: 'Name' })).toHaveAttribute('aria-sort', 'descending');
  expect(screen.getAllByRole('row')[1]).toHaveTextContent('Zürich');
});
test('checkbox Space changes selection once without opening a row', async () => {
  const select = jest.fn(); const open = jest.fn();
  render(<DataTable columns={columns} rows={rows} getRowId={row => row.id} getRowLabel={row => row.name} selectedIds={new Set()} onSelectionChange={select} onRowClick={open} />);
  screen.getByRole('checkbox', { name: 'Zürich auswählen' }).focus(); await userEvent.keyboard(' ');
  expect(select).toHaveBeenCalledTimes(1); expect(select).toHaveBeenCalledWith(new Set(['1'])); expect(open).not.toHaveBeenCalled();
  screen.getByRole('button', { name: 'Details für Zürich' }).focus(); await userEvent.keyboard('{Enter}'); expect(open).toHaveBeenCalledWith(rows[0]);
});
test('select all changes only the displayed page', async () => {
  const select = jest.fn();
  const { rerender } = render(<DataTable columns={columns} rows={rows} getRowId={row => row.id} selectedIds={new Set(['elsewhere'])} onSelectionChange={select} />);
  await userEvent.click(screen.getByRole('checkbox', { name: 'Alle angezeigten Einträge auswählen' }));
  expect(select).toHaveBeenLastCalledWith(new Set(['elsewhere', '1', '2']));
  rerender(<DataTable columns={columns} rows={rows} getRowId={row => row.id} selectedIds={new Set(['elsewhere', '1', '2'])} onSelectionChange={select} />);
  await userEvent.click(screen.getByRole('checkbox', { name: 'Alle angezeigten Einträge auswählen' }));
  expect(select).toHaveBeenLastCalledWith(new Set(['elsewhere']));
});
test('server sorting requests a sort without rearranging a partial page', async () => {
  const sort = jest.fn();
  render(<DataTable columns={columns} rows={rows} getRowId={row => row.id} onSortChange={sort} />);
  await userEvent.click(screen.getByRole('button', { name: 'Name' }));
  expect(sort).toHaveBeenCalledWith({ key: 'name', direction: 'asc' });
  expect(screen.getAllByRole('row')[1]).toHaveTextContent('Zürich');
});
