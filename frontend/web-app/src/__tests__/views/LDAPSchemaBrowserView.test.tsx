import React from 'react';
import { render, screen, act, fireEvent, waitFor } from '@testing-library/react';
import LDAPSchemaBrowserView from '../../components/views/LDAPSchemaBrowserView';
import { api } from '../../lib/api';

const mockedApi = api as jest.Mocked<typeof api>;

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('LDAPSchemaBrowserView', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Return empty schema by default
    mockedApi.get = jest.fn().mockResolvedValue({
      data: { objectClasses: [], attributeTypes: [] },
    });
  });

  test('renders without crashing', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });
    expect(document.body).toBeTruthy();
  });

  test('renders the LDAP Schema Browser heading', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });
    expect(screen.getByText('LDAP Schema Browser')).toBeInTheDocument();
  });

  test('both "Object Classes" and "Attribute Types" tabs are visible', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });
    expect(screen.getByText(/Object Classes/)).toBeInTheDocument();
    expect(screen.getByText(/Attribute Types/)).toBeInTheDocument();
  });

  test('search input renders', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });
    const input = screen.getByPlaceholderText(/Search object classes/i);
    expect(input).toBeInTheDocument();
  });

  test('"Add Object Class" button is present when on Object Classes tab', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });
    expect(screen.getByText('Add Object Class')).toBeInTheDocument();
  });

  test('clicking "Attribute Types" tab switches to attribute section', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });

    const atTab = screen.getByText(/Attribute Types/);
    fireEvent.click(atTab);

    await waitFor(() => {
      // After switching tabs the search placeholder changes
      expect(screen.getByPlaceholderText(/Search attribute types/i)).toBeInTheDocument();
    });
  });

  test('"Add Attribute Type" button appears after switching to Attribute Types tab', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });

    const atTab = screen.getByText(/Attribute Types/);
    fireEvent.click(atTab);

    await waitFor(() => {
      expect(screen.getByText('Add Attribute Type')).toBeInTheDocument();
    });
  });

  test('api.get is called for object-classes and attribute-types on mount', async () => {
    await act(async () => {
      render(<LDAPSchemaBrowserView />);
    });

    expect(mockedApi.get).toHaveBeenCalledWith('/api/schema/object-classes');
    expect(mockedApi.get).toHaveBeenCalledWith('/api/schema/attribute-types');
  });
});
