'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  MagnifyingGlassIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  ComputerDesktopIcon,
  CommandLineIcon,
  ShieldCheckIcon,
  ChatBubbleLeftRightIcon,
  WrenchIcon,
  BriefcaseIcon,
  PhotoIcon,
  CodeBracketIcon,
  Cog6ToothIcon,
  PlusIcon,
  XMarkIcon,
  ChevronRightIcon,
  TagIcon,
  KeyIcon,
  ChartBarIcon,
  UserGroupIcon,
  BuildingOfficeIcon,
  ServerIcon,
  RocketLaunchIcon,
  ClockIcon,
  NoSymbolIcon,
} from '@heroicons/react/24/outline';
import { appStoreApi } from '@/lib/api';
import { useUiMode } from '@/lib/ui-mode';
import SimpleViewLayout from '@/components/shared/SimpleViewLayout';
import toast from 'react-hot-toast';

// --- Types ---
interface StoreApp {
  id: string;
  name: string;
  display_name: string;
  description: string;
  category: string;
  publisher: string;
  icon_url: string | null;
  homepage_url: string | null;
  version: string;
  platforms: string[];
  packages: Record<string, { type: string; id: string; cask?: boolean; args?: string }>;
  size_bytes: number | null;
  license_type: string;
  max_licenses: number | null;
  used_licenses: number;
  required: boolean;
  tags: string[];
  metadata: Record<string, any>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  install_type?: string;
}

interface StoreCategory {
  id: string;
  name: string;
  display_name: string;
  icon: string;
  sort_order: number;
}

interface Installation {
  id: string;
  app_id: string;
  device_id: string;
  user_id: string;
  version: string;
  status: string;
  progress: number;
  error_message: string | null;
  installed_at: string | null;
  requested_at: string;
  app_name?: string;
  display_name?: string;
  category?: string;
  icon_url?: string;
  packages?: Record<string, any>;
  platforms?: string[];
}

interface StoreStats {
  apps: { total: number; enabled: number };
  installations: { total: number; installed: number; pending: number; failed: number };
  categories: { category: string; count: string }[];
  licenses: { licensedApps: number; totalUsedLicenses: number };
}

interface Assignment {
  id: string;
  app_id: string;
  target_type: string;
  target_id: string;
  target_name: string;
  install_type: string;
  created_at: string;
  created_by: string;
}

interface DeploymentTarget {
  type: 'device' | 'group' | 'user';
  id: string;
  name?: string;
}

interface Deployment {
  id: string;
  app_id: string;
  app_name?: string;
  targets: DeploymentTarget[];
  version?: string;
  status: string;
  mandatory: boolean;
  deadline?: string | null;
  created_at: string;
  completed_at?: string | null;
  created_by?: string;
  progress?: { total: number; installed: number; failed: number; pending: number };
}

interface AppPackage {
  id: string;
  app_id: string;
  platform: 'windows' | 'macos' | 'linux';
  format: string;
  version: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  architecture: string;
  release_notes: string;
  uploaded_at: string;
  download_count: number;
}

interface PackageSummary {
  windows: AppPackage | null;
  macos: AppPackage | null;
  linux: AppPackage | null;
}

// --- Helpers ---
const categoryIcons: Record<string, React.ComponentType<any>> = {
  browser: GlobeAltIcon,
  development: CodeBracketIcon,
  productivity: BriefcaseIcon,
  communication: ChatBubbleLeftRightIcon,
  security: ShieldCheckIcon,
  utilities: WrenchIcon,
  media: PhotoIcon,
  system: Cog6ToothIcon,
};

const categoryColors: Record<string, { bg: string; text: string }> = {
  browser: { bg: 'bg-blue-100', text: 'text-blue-600' },
  development: { bg: 'bg-purple-100', text: 'text-purple-600' },
  productivity: { bg: 'bg-green-100', text: 'text-green-600' },
  communication: { bg: 'bg-indigo-100', text: 'text-indigo-600' },
  security: { bg: 'bg-red-100', text: 'text-red-600' },
  utilities: { bg: 'bg-yellow-100', text: 'text-yellow-600' },
  media: { bg: 'bg-pink-100', text: 'text-pink-600' },
  system: { bg: 'bg-gray-100', text: 'text-gray-600' },
};

const platformLabels: Record<string, { label: string; icon: React.ComponentType<any> }> = {
  windows: { label: 'Windows', icon: ComputerDesktopIcon },
  macos: { label: 'macOS', icon: ComputerDesktopIcon },
  linux: { label: 'Linux', icon: CommandLineIcon },
};

function getCategoryIcon(category: string) {
  return categoryIcons[category] || Cog6ToothIcon;
}

function getCategoryColor(category: string) {
  return categoryColors[category] || { bg: 'bg-gray-100', text: 'text-gray-600' };
}

// --- Component ---
interface AppStoreViewProps {
  onOpenWizard?: () => void;
}

export default function AppStoreView({ onOpenWizard }: AppStoreViewProps) {
  const { isSimple } = useUiMode();
  const [apps, setApps] = useState<StoreApp[]>([]);
  const [categories, setCategories] = useState<StoreCategory[]>([]);
  const [stats, setStats] = useState<StoreStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedApp, setSelectedApp] = useState<StoreApp | null>(null);
  const [activeTab, setActiveTab] = useState<'available' | 'installed' | 'required' | 'admin' | 'deployments'>('available');
  const [installedApps, setInstalledApps] = useState<Installation[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [installingApps, setInstallingApps] = useState<Set<string>>(new Set());
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [assignTarget, setAssignTarget] = useState({ target_type: 'domain', target_id: '', target_name: '' });
  const [assignInstallType, setAssignInstallType] = useState('available');
  const [showShareAppModal, setShowShareAppModal] = useState(false);
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [deployTarget, setDeployTarget] = useState<StoreApp | null>(null);
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [deploying, setDeploying] = useState(false);

  // Package distribution state
  const [showPackageModal, setShowPackageModal] = useState(false);
  const [packageTarget, setPackageTarget] = useState<StoreApp | null>(null);
  const [packageSummaries, setPackageSummaries] = useState<Record<string, PackageSummary>>({});
  const [uploadingPkg, setUploadingPkg] = useState(false);
  const [pkgFile, setPkgFile] = useState<File | null>(null);
  const [pkgVersion, setPkgVersion] = useState('');
  const [pkgArch, setPkgArch] = useState('x64');
  const [pkgReleaseNotes, setPkgReleaseNotes] = useState('');
  const [pkgDragOver, setPkgDragOver] = useState(false);

  // Device ID for demo/self-service - in production this comes from the client agent
  const deviceId = 'self-service';

  // --- Data Loading ---
  const loadCatalog = useCallback(async () => {
    try {
      const [catalogRes, categoriesRes, statsRes] = await Promise.all([
        appStoreApi.getCatalog({ search: searchTerm, category: selectedCategory !== 'all' ? selectedCategory : undefined }),
        appStoreApi.getCategories(),
        appStoreApi.getStats(),
      ]);
      setApps(catalogRes.data.apps || []);
      setCategories(categoriesRes.data || []);
      setStats(statsRes.data || null);
    } catch (error) {
      console.error('Failed to load catalog:', error);
      toast.error('Failed to load app catalog');
    } finally {
      setLoading(false);
    }
  }, [searchTerm, selectedCategory]);

  const loadInstalled = useCallback(async () => {
    try {
      const res = await appStoreApi.getInstalled(deviceId);
      setInstalledApps(res.data || []);
    } catch (error) {
      console.error('Failed to load installed apps:', error);
    }
  }, []);

  useEffect(() => {
    loadCatalog();
    loadInstalled();
  }, [loadCatalog, loadInstalled]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      loadCatalog();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm, selectedCategory, loadCatalog]);

  // --- Actions ---
  const handleInstall = async (app: StoreApp) => {
    try {
      setInstallingApps((prev) => new Set(prev).add(app.id));
      await appStoreApi.requestInstall({ appId: app.id, deviceId });
      toast.success(`Installing ${app.display_name}...`);
      loadInstalled();
    } catch (error: any) {
      const msg = error.response?.data?.error || 'Installation failed';
      toast.error(msg);
    } finally {
      setInstallingApps((prev) => {
        const next = new Set(prev);
        next.delete(app.id);
        return next;
      });
    }
  };

  const handleUninstall = async (app: StoreApp) => {
    try {
      await appStoreApi.requestUninstall({ appId: app.id, deviceId });
      toast.success(`Uninstalling ${app.display_name}...`);
      loadInstalled();
    } catch (error: any) {
      const msg = error.response?.data?.error || 'Uninstall failed';
      toast.error(msg);
    }
  };

  const handleSeedApps = async () => {
    try {
      await appStoreApi.seedCatalog();
      toast.success('Default apps seeded successfully');
      loadCatalog();
    } catch (error) {
      toast.error('Failed to seed apps');
    }
  };

  const handleDeleteApp = async (appId: string) => {
    try {
      await appStoreApi.deleteApp(appId);
      toast.success('App removed from catalog');
      setSelectedApp(null);
      loadCatalog();
    } catch (error) {
      toast.error('Failed to delete app');
    }
  };

  const handleAssign = async () => {
    if (!selectedApp) return;
    try {
      await appStoreApi.assignApp(selectedApp.id, {
        targets: [assignTarget],
        install_type: assignInstallType,
      });
      toast.success('App assigned successfully');
      setShowAssignModal(false);
      loadAppAssignments(selectedApp.id);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to assign app');
    }
  };

  const handleRemoveAssignment = async (appId: string, assignId: string) => {
    try {
      await appStoreApi.removeAssignment(appId, assignId);
      toast.success('Assignment removed');
      loadAppAssignments(appId);
    } catch (error) {
      toast.error('Failed to remove assignment');
    }
  };

  const loadAppAssignments = async (appId: string) => {
    try {
      const res = await appStoreApi.getAssignments(appId);
      setAssignments(res.data || []);
    } catch (error) {
      console.error('Failed to load assignments:', error);
    }
  };

  const loadDeployments = useCallback(async () => {
    try {
      const res = await fetch('/api/appstore/deployments');
      if (res.ok) {
        const data = await res.json();
        setDeployments(data.deployments || []);
      }
    } catch (error) {
      console.error('Failed to load deployments:', error);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'deployments') loadDeployments();
  }, [activeTab, loadDeployments]);

  const handleCancelDeployment = async (deploymentId: string) => {
    try {
      const res = await fetch(`/api/appstore/deployments/${deploymentId}/cancel`, { method: 'PUT' });
      if (res.ok) {
        toast.success('Deployment abgebrochen');
        loadDeployments();
      } else {
        const data = await res.json();
        toast.error(data.error || 'Fehler beim Abbrechen');
      }
    } catch {
      toast.error('Fehler beim Abbrechen des Deployments');
    }
  };

  // --- Package distribution helpers ---
  const loadPackageSummary = async (appId: string) => {
    try {
      const res = await fetch(`/api/appstore/apps/${appId}/packages/summary`);
      if (res.ok) {
        const data = await res.json();
        setPackageSummaries(prev => ({ ...prev, [appId]: data }));
      }
    } catch {}
  };

  const handleOpenPackageModal = (app: StoreApp) => {
    setPackageTarget(app);
    setPkgFile(null); setPkgVersion(''); setPkgArch('x64'); setPkgReleaseNotes('');
    setShowPackageModal(true);
    loadPackageSummary(app.id);
  };

  const handlePackageUpload = async () => {
    if (!pkgFile || !packageTarget) return;
    if (!pkgVersion.trim()) { toast.error('Bitte Version angeben'); return; }
    setUploadingPkg(true);
    try {
      const form = new FormData();
      form.append('file', pkgFile);
      form.append('version', pkgVersion);
      form.append('architecture', pkgArch);
      form.append('release_notes', pkgReleaseNotes);
      const res = await fetch(`/api/appstore/apps/${packageTarget.id}/packages`, { method: 'POST', body: form });
      if (res.ok) {
        toast.success('Paket hochgeladen');
        setPkgFile(null); setPkgVersion('');
        loadPackageSummary(packageTarget.id);
      } else {
        const d = await res.json();
        toast.error(d.error || 'Upload fehlgeschlagen');
      }
    } catch {
      toast.error('Upload fehlgeschlagen');
    } finally {
      setUploadingPkg(false);
    }
  };

  const handlePackageDownload = (pkg: AppPackage) => {
    const a = document.createElement('a');
    a.href = `/api/appstore/packages/${pkg.id}/download`;
    a.download = pkg.filename;
    a.click();
  };

  const handlePackageDelete = async (pkgId: string, appId: string) => {
    try {
      const res = await fetch(`/api/appstore/packages/${pkgId}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success('Paket gelöscht');
        loadPackageSummary(appId);
      }
    } catch { toast.error('Fehler beim Löschen'); }
  };

  const fmtBytes = (b: number) => {
    if (!b) return '—';
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
    return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
  };

  const PLATFORM_INFO = {
    windows: { label: 'Windows', color: 'bg-blue-100 text-blue-700', ext: '.exe / .msi / .msix' },
    macos:   { label: 'macOS',   color: 'bg-gray-100 text-gray-700',  ext: '.dmg / .pkg' },
    linux:   { label: 'Linux',   color: 'bg-orange-100 text-orange-700', ext: '.deb / .rpm / .AppImage' },
  };

  // --- Filtered apps ---
  const filteredApps = apps.filter((app) => {
    if (activeTab === 'required') return app.required;
    return true;
  });

  const isInstalled = (appId: string) => {
    return installedApps.some((i) => i.app_id === appId && i.status === 'installed');
  };

  const getInstallStatus = (appId: string) => {
    const install = installedApps.find((i) => i.app_id === appId);
    return install?.status || null;
  };

  // --- Render ---
  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-64 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div className="h-12 w-12 bg-gray-200 rounded-xl mb-4"></div>
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-gray-200 rounded w-1/2 mb-4"></div>
                <div className="h-20 bg-gray-200 rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ── Simple Mode: Clean app grid, no tabs, just browse & install ──
  if (isSimple) {
    return (
      <SimpleViewLayout
        hero={{
          status: 'ok',
          icon: <ArrowDownTrayIcon className="w-10 h-10 text-green-600" />,
          title: 'App Store',
          subtitle: `${stats?.apps.total ?? 0} apps available · ${stats?.installations.installed ?? 0} installed`,
        }}
        stats={[
          { value: stats?.apps.total ?? 0, label: 'Total Apps' },
          { value: stats?.installations.installed ?? 0, label: 'Installed', color: 'text-green-600' },
          { value: stats?.installations.pending ?? 0, label: 'Pending', color: 'text-yellow-600' },
          { value: stats?.installations.failed ?? 0, label: 'Failed', color: 'text-red-600' },
        ]}
      >
        {/* Search */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
          </div>
          <input
            type="text"
            placeholder="Search apps..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="block w-full pl-10 pr-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white"
          />
        </div>

        {/* App Grid - simplified cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filteredApps.map((app) => {
            const color = getCategoryColor(app.category);
            const Icon = getCategoryIcon(app.category);
            const installed = isInstalled(app.id);
            const isInstalling2 = installingApps.has(app.id);
            const installStatus = getInstallStatus(app.id);

            return (
              <div key={app.id} className="bg-white rounded-xl border border-gray-100 shadow-sm p-4 hover:shadow-md transition-all">
                <div className="flex items-center space-x-3 mb-3">
                  <div className={`w-10 h-10 ${color.bg} rounded-xl flex items-center justify-center flex-shrink-0`}>
                    <Icon className={`w-5 h-5 ${color.text}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-semibold text-gray-900 truncate">{app.display_name}</h3>
                    <p className="text-xs text-gray-500">v{app.version}</p>
                  </div>
                </div>
                <p className="text-xs text-gray-600 mb-3 line-clamp-2">{app.description}</p>
                <button
                  onClick={() => {
                    if (installed) handleUninstall(app);
                    else handleInstall(app);
                  }}
                  disabled={isInstalling2 || installStatus === 'installing' || installStatus === 'downloading'}
                  className={`w-full py-2 rounded-lg text-xs font-medium transition-colors ${
                    installed
                      ? 'bg-gray-100 text-gray-600 hover:bg-red-50 hover:text-red-600'
                      : isInstalling2 || installStatus === 'installing'
                      ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                      : 'bg-blue-600 text-white hover:bg-blue-700'
                  }`}
                >
                  {installed ? 'Installed' : isInstalling2 ? 'Installing...' : 'Install'}
                </button>
              </div>
            );
          })}
        </div>

        {filteredApps.length === 0 && (
          <div className="text-center py-12">
            <MagnifyingGlassIcon className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <p className="text-sm text-gray-500">No apps found</p>
            {apps.length === 0 && (
              <button onClick={handleSeedApps} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
                Seed Default Apps
              </button>
            )}
          </div>
        )}
      </SimpleViewLayout>
    );
  }

  // ── Expert Mode: Full UI with all tabs ──
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">App Store</h1>
          <p className="text-sm text-gray-500 mt-1">
            Browse, install, and manage enterprise applications
          </p>
        </div>

        <div className="flex items-center gap-3">
          {onOpenWizard && (
            <button onClick={onOpenWizard} className="px-3 py-1.5 rounded-lg bg-violet-50 hover:bg-violet-100 text-violet-700 text-sm font-medium transition-colors">
              Verteilungs-Assistent
            </button>
          )}
        </div>
        {/* Stats badges */}
        {stats && (
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center space-x-1 text-gray-500">
              <ChartBarIcon className="w-4 h-4" />
              <span>{stats.apps.total} Apps</span>
            </div>
            <div className="flex items-center space-x-1 text-green-600">
              <CheckCircleIcon className="w-4 h-4" />
              <span>{stats.installations.installed} Installed</span>
            </div>
            {stats.installations.pending > 0 && (
              <div className="flex items-center space-x-1 text-yellow-600">
                <ArrowPathIcon className="w-4 h-4" />
                <span>{stats.installations.pending} Pending</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'available' as const, label: 'Available Apps', icon: ArrowDownTrayIcon },
            { id: 'installed' as const, label: 'Installed', icon: CheckCircleIcon },
            { id: 'required' as const, label: 'Required', icon: ExclamationTriangleIcon },
            { id: 'deployments' as const, label: 'Deployments', icon: RocketLaunchIcon },
            { id: 'admin' as const, label: 'Admin', icon: Cog6ToothIcon },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-3 px-1 border-b-2 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-4">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <MagnifyingGlassIcon className="h-4 w-4 text-gray-400" />
          </div>
          <input
            type="text"
            placeholder="Search apps by name, description, or tags..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>

        {/* Category filter tabs */}
        <div className="flex items-center space-x-1 overflow-x-auto pb-1">
          <button
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-full whitespace-nowrap transition-colors ${
              selectedCategory === 'all'
                ? 'bg-blue-100 text-blue-700'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            All
          </button>
          {categories.map((cat) => {
            const CatIcon = getCategoryIcon(cat.name);
            return (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.name)}
                className={`flex items-center space-x-1 px-3 py-1.5 text-xs font-medium rounded-full whitespace-nowrap transition-colors ${
                  selectedCategory === cat.name
                    ? 'bg-blue-100 text-blue-700'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                <CatIcon className="w-3 h-3" />
                <span>{cat.display_name}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Admin Tab Content */}
      {activeTab === 'admin' && (
        <div className="space-y-4">
          <div className="flex items-center space-x-3">
            <button
              onClick={handleSeedApps}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
            >
              <PlusIcon className="w-4 h-4" />
              <span>Seed Default Apps</span>
            </button>
            <button
              onClick={() => setShowShareAppModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm font-medium"
            >
              <ServerIcon className="w-4 h-4" />
              <span>App aus File Share</span>
            </button>
          </div>

          {/* License overview */}
          {stats && stats.licenses.licensedApps > 0 && (
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center space-x-2">
                <KeyIcon className="w-5 h-5 text-gray-400" />
                <span>License Overview</span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500">Licensed Apps</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats.licenses.licensedApps}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500">Used Licenses</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats.licenses.totalUsedLicenses}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500">Total Installations</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats.installations.total}</p>
                </div>
              </div>
            </div>
          )}

          {/* Stats by category */}
          {stats && stats.categories.length > 0 && (
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Apps by Category</h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {stats.categories.map((cat) => {
                  const color = getCategoryColor(cat.category);
                  const Icon = getCategoryIcon(cat.category);
                  return (
                    <div key={cat.category} className={`${color.bg} rounded-lg p-3 flex items-center space-x-3`}>
                      <Icon className={`w-5 h-5 ${color.text}`} />
                      <div>
                        <p className={`text-sm font-medium ${color.text}`}>{cat.category}</p>
                        <p className="text-xs text-gray-500">{cat.count} apps</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Installed Tab Content */}
      {activeTab === 'installed' && (
        <div className="space-y-4">
          {installedApps.length === 0 ? (
            <div className="text-center py-12">
              <ArrowDownTrayIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No installed apps</h3>
              <p className="text-sm text-gray-500">Browse the catalog and install apps to see them here</p>
            </div>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">App</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Progress</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Installed</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {installedApps.map((install) => (
                    <tr key={install.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-3">
                          <div className={`w-8 h-8 ${getCategoryColor(install.category || '').bg} rounded-lg flex items-center justify-center`}>
                            {React.createElement(getCategoryIcon(install.category || ''), { className: `w-4 h-4 ${getCategoryColor(install.category || '').text}` })}
                          </div>
                          <span className="text-sm font-medium text-gray-900">{install.display_name || install.app_name || 'Unknown'}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{install.version}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <StatusBadge status={install.status} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {install.status !== 'installed' && install.status !== 'failed' && (
                          <div className="w-24 bg-gray-200 rounded-full h-2">
                            <div
                              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${install.progress}%` }}
                            />
                          </div>
                        )}
                        {install.status === 'installed' && <span className="text-xs text-green-600">Complete</span>}
                        {install.status === 'failed' && <span className="text-xs text-red-600">{install.error_message || 'Error'}</span>}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {install.installed_at ? new Date(install.installed_at).toLocaleDateString() : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Available & Required Tabs - App Grid */}
      {(activeTab === 'available' || activeTab === 'required') && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {filteredApps.map((app) => {
              const color = getCategoryColor(app.category);
              const Icon = getCategoryIcon(app.category);
              const installed = isInstalled(app.id);
              const installStatus = getInstallStatus(app.id);
              const isInstalling = installingApps.has(app.id);

              return (
                <div
                  key={app.id}
                  className="bg-white rounded-xl shadow-sm border border-gray-100 p-5 hover:shadow-md transition-all duration-200 cursor-pointer flex flex-col"
                  onClick={() => {
                    setSelectedApp(app);
                    loadAppAssignments(app.id);
                  }}
                >
                  {/* App icon and info */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`w-11 h-11 ${color.bg} rounded-xl flex items-center justify-center flex-shrink-0`}>
                        <Icon className={`w-6 h-6 ${color.text}`} />
                      </div>
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-gray-900 truncate">{app.display_name}</h3>
                        <p className="text-xs text-gray-500">{app.publisher || app.category}</p>
                      </div>
                    </div>
                    {app.required && (
                      <span className="px-2 py-0.5 text-xs font-medium bg-red-100 text-red-700 rounded-full flex-shrink-0">
                        Required
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  <p className="text-xs text-gray-600 mb-3 line-clamp-2 flex-1">{app.description}</p>

                  {/* Platform badges */}
                  <div className="flex items-center space-x-1 mb-3">
                    {(app.platforms || []).map((p) => {
                      const plat = platformLabels[p];
                      if (!plat) return null;
                      return (
                        <span key={p} className="inline-flex items-center space-x-1 px-2 py-0.5 bg-gray-100 rounded text-xs text-gray-600">
                          <plat.icon className="w-3 h-3" />
                          <span>{plat.label}</span>
                        </span>
                      );
                    })}
                  </div>

                  {/* Footer: version + license + buttons */}
                  <div className="flex items-center justify-between pt-3 border-t border-gray-100">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-gray-500">v{app.version}</span>
                      {app.license_type !== 'free' && (
                        <span className="flex items-center space-x-0.5 text-xs text-yellow-600">
                          <KeyIcon className="w-3 h-3" />
                          <span>{app.license_type}</span>
                        </span>
                      )}
                      {app.license_type !== 'free' && app.max_licenses && (
                        <span className="text-xs text-gray-400">
                          {app.used_licenses}/{app.max_licenses}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-1.5">
                      {/* Packages button */}
                      <button
                        onClick={(e) => { e.stopPropagation(); handleOpenPackageModal(app); }}
                        className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-50 text-emerald-700 hover:bg-emerald-100 transition-colors"
                        title="Pakete verwalten"
                      >
                        <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                        <span>Pakete</span>
                        {packageSummaries[app.id] && Object.values(packageSummaries[app.id]).some(Boolean) && (
                          <span className="ml-0.5 bg-emerald-600 text-white rounded-full px-1 text-[10px]">
                            {Object.values(packageSummaries[app.id]).filter(Boolean).length}
                          </span>
                        )}
                      </button>

                      {/* Deploy button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeployTarget(app);
                          setShowDeployModal(true);
                        }}
                        className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-violet-50 text-violet-700 hover:bg-violet-100 transition-colors"
                        title="App deployen"
                      >
                        <RocketLaunchIcon className="w-3.5 h-3.5" />
                        <span>Deployen</span>
                      </button>

                      {/* Install button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (installed) {
                            handleUninstall(app);
                          } else {
                            handleInstall(app);
                          }
                        }}
                        disabled={isInstalling || installStatus === 'installing' || installStatus === 'downloading'}
                        className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                          installed
                            ? 'bg-red-50 text-red-600 hover:bg-red-100'
                            : isInstalling || installStatus === 'installing' || installStatus === 'downloading'
                              ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                              : 'bg-blue-600 text-white hover:bg-blue-700'
                        }`}
                      >
                        {installed ? (
                          <>
                            <TrashIcon className="w-3.5 h-3.5" />
                            <span>Remove</span>
                          </>
                        ) : isInstalling || installStatus === 'installing' || installStatus === 'downloading' ? (
                          <>
                            <ArrowPathIcon className="w-3.5 h-3.5 animate-spin" />
                            <span>Installing</span>
                          </>
                        ) : (
                          <>
                            <ArrowDownTrayIcon className="w-3.5 h-3.5" />
                            <span>Install</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* No results */}
          {filteredApps.length === 0 && (
            <div className="text-center py-12">
              <MagnifyingGlassIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No apps found</h3>
              <p className="text-sm text-gray-500">
                {activeTab === 'required'
                  ? 'No required apps are configured'
                  : 'Try adjusting your search or filter criteria'}
              </p>
              {apps.length === 0 && (
                <button
                  onClick={handleSeedApps}
                  className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
                >
                  Seed Default Apps
                </button>
              )}
            </div>
          )}
        </>
      )}

      {/* Deployments Tab Content */}
      {activeTab === 'deployments' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-gray-900">Aktive Deployments</h2>
            <button
              onClick={loadDeployments}
              className="flex items-center space-x-1 px-3 py-1.5 text-xs font-medium text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
            >
              <ArrowPathIcon className="w-3.5 h-3.5" />
              <span>Aktualisieren</span>
            </button>
          </div>

          {deployments.length === 0 ? (
            <div className="text-center py-12">
              <RocketLaunchIcon className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Keine Deployments</h3>
              <p className="text-sm text-gray-500">Klicken Sie auf «Deployen» bei einer App um ein Deployment zu starten</p>
            </div>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">App</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Ziele</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Fortschritt</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Erstellt</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Aktion</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {deployments.map((dep) => {
                    const progress = dep.progress || { total: dep.targets?.length || 0, installed: 0, failed: 0, pending: dep.targets?.length || 0 };
                    const pct = progress.total > 0 ? Math.round((progress.installed / progress.total) * 100) : 0;
                    return (
                      <tr key={dep.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <p className="text-sm font-medium text-gray-900">{dep.app_name || dep.app_id}</p>
                            <p className="text-xs text-gray-500">v{dep.version || '–'}</p>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {dep.targets?.length || 0} {dep.mandatory && <span className="ml-1 px-1.5 py-0.5 text-xs bg-red-100 text-red-700 rounded">Pflicht</span>}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center space-x-2">
                            <div className="w-24 bg-gray-200 rounded-full h-2">
                              <div
                                className={`h-2 rounded-full transition-all ${progress.failed > 0 ? 'bg-red-500' : 'bg-blue-500'}`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-500 whitespace-nowrap">
                              {progress.installed}/{progress.total} Geräte
                            </span>
                          </div>
                          {progress.failed > 0 && (
                            <p className="text-xs text-red-600 mt-0.5">{progress.failed} Fehler</p>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <DeploymentStatusBadge status={dep.status} />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(dep.created_at).toLocaleDateString('de-CH')}
                          {dep.deadline && (
                            <p className="text-xs text-orange-600 flex items-center space-x-0.5 mt-0.5">
                              <ClockIcon className="w-3 h-3" />
                              <span>{new Date(dep.deadline).toLocaleDateString('de-CH')}</span>
                            </p>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {(dep.status === 'pending' || dep.status === 'running') && (
                            <button
                              onClick={() => handleCancelDeployment(dep.id)}
                              className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg transition-colors"
                            >
                              <NoSymbolIcon className="w-3.5 h-3.5" />
                              <span>Abbrechen</span>
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Package Distribution Modal */}
      {showPackageModal && packageTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.4)' }}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-100">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">Pakete verwalten</h2>
                <p className="text-sm text-gray-500 mt-0.5">{packageTarget.name}</p>
              </div>
              <button onClick={() => setShowPackageModal(false)} className="p-2 hover:bg-gray-100 rounded-lg">
                <XMarkIcon className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Platform availability */}
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">Verfügbare Plattform-Pakete</h3>
                <div className="grid grid-cols-3 gap-3">
                  {(['windows', 'macos', 'linux'] as const).map(platform => {
                    const info = PLATFORM_INFO[platform];
                    const pkg = packageSummaries[packageTarget.id]?.[platform];
                    return (
                      <div key={platform} className={`rounded-xl border-2 p-3 ${pkg ? 'border-emerald-200 bg-emerald-50' : 'border-dashed border-gray-200 bg-gray-50'}`}>
                        <div className="flex items-center justify-between mb-1">
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${info.color}`}>{info.label}</span>
                          {pkg && <span className="text-[10px] text-gray-400">v{pkg.version}</span>}
                        </div>
                        {pkg ? (
                          <div className="space-y-1.5 mt-2">
                            <p className="text-xs text-gray-600 truncate" title={pkg.filename}>{pkg.filename}</p>
                            <p className="text-xs text-gray-400">{fmtBytes(pkg.size_bytes)} · {pkg.download_count} Downloads</p>
                            <div className="flex gap-1.5 mt-2">
                              <button
                                onClick={() => handlePackageDownload(pkg)}
                                className="flex-1 flex items-center justify-center gap-1 px-2 py-1 bg-emerald-600 text-white rounded-lg text-xs font-medium hover:bg-emerald-700"
                              >
                                <ArrowDownTrayIcon className="w-3 h-3" />
                                Download
                              </button>
                              <button
                                onClick={() => handlePackageDelete(pkg.id, packageTarget.id)}
                                className="p-1 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg"
                                title="Paket löschen"
                              >
                                <TrashIcon className="w-3.5 h-3.5" />
                              </button>
                            </div>
                            {pkg.sha256 && (
                              <p className="text-[10px] text-gray-300 font-mono break-all">SHA256: {pkg.sha256.slice(0, 16)}…</p>
                            )}
                          </div>
                        ) : (
                          <div className="mt-2 text-center">
                            <p className="text-xs text-gray-400">Kein Paket</p>
                            <p className="text-[10px] text-gray-300 mt-0.5">{info.ext}</p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Upload section */}
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">Neues Paket hochladen</h3>

                {/* Drop zone */}
                <div
                  className={`border-2 border-dashed rounded-xl p-6 text-center transition-colors cursor-pointer ${pkgDragOver ? 'border-blue-400 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
                  onDragOver={e => { e.preventDefault(); setPkgDragOver(true); }}
                  onDragLeave={() => setPkgDragOver(false)}
                  onDrop={e => {
                    e.preventDefault();
                    setPkgDragOver(false);
                    const f = e.dataTransfer.files[0];
                    if (f) { setPkgFile(f); if (!pkgVersion) setPkgVersion('1.0.0'); }
                  }}
                  onClick={() => document.getElementById('pkg-file-input')?.click()}
                >
                  <input
                    id="pkg-file-input"
                    type="file"
                    className="hidden"
                    accept=".exe,.msi,.msix,.dmg,.pkg,.deb,.rpm,.AppImage,.tar.gz,.tar.xz,.zip"
                    onChange={e => {
                      const f = e.target.files?.[0];
                      if (f) { setPkgFile(f); if (!pkgVersion) setPkgVersion('1.0.0'); }
                    }}
                  />
                  <ArrowDownTrayIcon className="w-8 h-8 text-gray-300 mx-auto mb-2" />
                  {pkgFile ? (
                    <div>
                      <p className="text-sm font-medium text-gray-800">{pkgFile.name}</p>
                      <p className="text-xs text-gray-400 mt-0.5">{fmtBytes(pkgFile.size)}</p>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm text-gray-500">Datei hier ablegen oder klicken</p>
                      <p className="text-xs text-gray-400 mt-1">.exe · .msi · .msix · .dmg · .pkg · .deb · .rpm · .AppImage · .tar.gz</p>
                    </div>
                  )}
                </div>

                {pkgFile && (
                  <div className="mt-3 grid grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <label className="block text-xs font-medium text-gray-600 mb-1">Version *</label>
                      <input
                        type="text"
                        value={pkgVersion}
                        onChange={e => setPkgVersion(e.target.value)}
                        placeholder="z.B. 2.5.1"
                        className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-600 mb-1">Architektur</label>
                      <select
                        value={pkgArch}
                        onChange={e => setPkgArch(e.target.value)}
                        className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="x64">x64</option>
                        <option value="arm64">arm64</option>
                        <option value="universal">Universal</option>
                        <option value="x86">x86</option>
                      </select>
                    </div>
                    <div className="col-span-3">
                      <label className="block text-xs font-medium text-gray-600 mb-1">Release Notes (optional)</label>
                      <textarea
                        value={pkgReleaseNotes}
                        onChange={e => setPkgReleaseNotes(e.target.value)}
                        rows={2}
                        placeholder="Was hat sich geändert?"
                        className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                      />
                    </div>
                  </div>
                )}

                <button
                  onClick={handlePackageUpload}
                  disabled={!pkgFile || !pkgVersion.trim() || uploadingPkg}
                  className="mt-3 w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-xl font-medium text-sm hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {uploadingPkg ? (
                    <>
                      <ArrowPathIcon className="w-4 h-4 animate-spin" />
                      Wird hochgeladen…
                    </>
                  ) : (
                    <>
                      <ArrowDownTrayIcon className="w-4 h-4 rotate-180" />
                      Paket hochladen
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Deploy Modal */}
      {showDeployModal && deployTarget && (
        <DeployModal
          app={deployTarget}
          onClose={() => { setShowDeployModal(false); setDeployTarget(null); }}
          onDeployed={() => {
            setShowDeployModal(false);
            setDeployTarget(null);
            setActiveTab('deployments');
            loadDeployments();
            toast.success('Deployment gestartet');
          }}
        />
      )}

      {/* App Detail Modal */}
      {selectedApp && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => {
            setSelectedApp(null);
            setShowAssignModal(false);
          }}
        >
          <div
            className="bg-white rounded-xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              {/* Modal Header */}
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <div className={`w-14 h-14 ${getCategoryColor(selectedApp.category).bg} rounded-xl flex items-center justify-center`}>
                    {React.createElement(getCategoryIcon(selectedApp.category), {
                      className: `w-8 h-8 ${getCategoryColor(selectedApp.category).text}`,
                    })}
                  </div>
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900">{selectedApp.display_name}</h2>
                    <p className="text-sm text-gray-500">
                      {selectedApp.publisher} &middot; v{selectedApp.version} &middot; {selectedApp.category}
                    </p>
                  </div>
                </div>
                <button onClick={() => setSelectedApp(null)} className="text-gray-400 hover:text-gray-600">
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>

              <div className="space-y-6">
                {/* Description */}
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Description</h3>
                  <p className="text-sm text-gray-600">{selectedApp.description}</p>
                </div>

                {/* Platform support */}
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Platform Support</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {(selectedApp.platforms || []).map((p) => {
                      const plat = platformLabels[p];
                      const pkg = selectedApp.packages[p];
                      if (!plat || !pkg) return null;
                      return (
                        <div key={p} className="bg-gray-50 rounded-lg p-3">
                          <div className="flex items-center space-x-2 mb-1">
                            <plat.icon className="w-4 h-4 text-gray-600" />
                            <span className="text-sm font-medium text-gray-900">{plat.label}</span>
                          </div>
                          <p className="text-xs text-gray-500">
                            {pkg.type}: {pkg.id}
                            {pkg.cask ? ' (cask)' : ''}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Tags */}
                {selectedApp.tags && selectedApp.tags.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Tags</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedApp.tags.map((tag) => (
                        <span key={tag} className="inline-flex items-center space-x-1 px-2 py-1 bg-gray-100 rounded-full text-xs text-gray-600">
                          <TagIcon className="w-3 h-3" />
                          <span>{tag}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* License info */}
                {selectedApp.license_type !== 'free' && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-2">
                      <KeyIcon className="w-4 h-4 text-yellow-600" />
                      <h3 className="text-sm font-medium text-yellow-800">License Information</h3>
                    </div>
                    <div className="flex items-center space-x-6 text-sm">
                      <span className="text-yellow-700">Type: {selectedApp.license_type}</span>
                      {selectedApp.max_licenses && (
                        <>
                          <span className="text-yellow-700">
                            Used: {selectedApp.used_licenses} / {selectedApp.max_licenses}
                          </span>
                          <div className="flex-1 max-w-[200px]">
                            <div className="w-full bg-yellow-200 rounded-full h-2">
                              <div
                                className="bg-yellow-500 h-2 rounded-full"
                                style={{
                                  width: `${Math.min(100, (selectedApp.used_licenses / selectedApp.max_licenses) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* Assignments (Admin) */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-medium text-gray-900">Assignments</h3>
                    <button
                      onClick={() => setShowAssignModal(true)}
                      className="flex items-center space-x-1 px-3 py-1.5 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 transition-colors text-xs font-medium"
                    >
                      <PlusIcon className="w-3.5 h-3.5" />
                      <span>Assign</span>
                    </button>
                  </div>

                  {assignments.length === 0 ? (
                    <p className="text-sm text-gray-500">No assignments. App is available to all users.</p>
                  ) : (
                    <div className="space-y-2">
                      {assignments.map((assign) => (
                        <div key={assign.id} className="flex items-center justify-between bg-gray-50 rounded-lg p-3">
                          <div className="flex items-center space-x-3">
                            <TargetTypeIcon type={assign.target_type} />
                            <div>
                              <p className="text-sm font-medium text-gray-900">
                                {assign.target_name || assign.target_id}
                              </p>
                              <p className="text-xs text-gray-500">
                                {assign.target_type} &middot; {assign.install_type}
                              </p>
                            </div>
                          </div>
                          <button
                            onClick={() => handleRemoveAssignment(selectedApp.id, assign.id)}
                            className="text-gray-400 hover:text-red-500"
                          >
                            <XMarkIcon className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Assign Modal Inline */}
                {showAssignModal && (
                  <div className="border border-blue-200 rounded-lg p-4 bg-blue-50">
                    <h4 className="text-sm font-medium text-blue-900 mb-3">New Assignment</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Target Type</label>
                        <select
                          value={assignTarget.target_type}
                          onChange={(e) => setAssignTarget({ ...assignTarget, target_type: e.target.value })}
                          className="block w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                        >
                          <option value="domain">Domain</option>
                          <option value="ou">OU</option>
                          <option value="group">Group</option>
                          <option value="device">Device</option>
                          <option value="user">User</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Target ID</label>
                        <input
                          type="text"
                          value={assignTarget.target_id}
                          onChange={(e) => setAssignTarget({ ...assignTarget, target_id: e.target.value })}
                          placeholder="e.g., corp.local"
                          className="block w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Install Type</label>
                        <select
                          value={assignInstallType}
                          onChange={(e) => setAssignInstallType(e.target.value)}
                          className="block w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                        >
                          <option value="available">Available</option>
                          <option value="required">Required</option>
                          <option value="uninstall">Uninstall</option>
                        </select>
                      </div>
                    </div>
                    <div className="flex justify-end space-x-2">
                      <button
                        onClick={() => setShowAssignModal(false)}
                        className="px-3 py-1.5 text-sm text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleAssign}
                        disabled={!assignTarget.target_id}
                        className="px-3 py-1.5 text-sm text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Assign
                      </button>
                    </div>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex justify-between pt-4 border-t border-gray-200">
                  <button
                    onClick={() => handleDeleteApp(selectedApp.id)}
                    className="px-4 py-2 text-sm font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg transition-colors"
                  >
                    Delete from Catalog
                  </button>
                  <div className="flex space-x-3">
                    <button
                      onClick={() => setSelectedApp(null)}
                      className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
                    >
                      Close
                    </button>
                    <button
                      onClick={() => {
                        if (isInstalled(selectedApp.id)) {
                          handleUninstall(selectedApp);
                        } else {
                          handleInstall(selectedApp);
                        }
                        setSelectedApp(null);
                      }}
                      className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${
                        isInstalled(selectedApp.id)
                          ? 'bg-red-600 hover:bg-red-700'
                          : 'bg-blue-600 hover:bg-blue-700'
                      }`}
                    >
                      {isInstalled(selectedApp.id) ? 'Uninstall' : 'Install'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Share App Modal */}
      {showShareAppModal && (
        <ShareAppModal
          categories={categories}
          onClose={() => setShowShareAppModal(false)}
          onSaved={() => { setShowShareAppModal(false); loadCatalog(); }}
        />
      )}
    </div>
  );
}

// --- Sub-components ---

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string; label: string }> = {
    installed: { bg: 'bg-green-100', text: 'text-green-700', label: 'Installed' },
    pending: { bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Pending' },
    downloading: { bg: 'bg-blue-100', text: 'text-blue-700', label: 'Downloading' },
    installing: { bg: 'bg-blue-100', text: 'text-blue-700', label: 'Installing' },
    failed: { bg: 'bg-red-100', text: 'text-red-700', label: 'Failed' },
    uninstalling: { bg: 'bg-orange-100', text: 'text-orange-700', label: 'Uninstalling' },
    uninstalled: { bg: 'bg-gray-100', text: 'text-gray-700', label: 'Uninstalled' },
  };

  const c = config[status] || { bg: 'bg-gray-100', text: 'text-gray-600', label: status };
  return (
    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${c.bg} ${c.text}`}>
      {c.label}
    </span>
  );
}

function TargetTypeIcon({ type }: { type: string }) {
  const icons: Record<string, React.ComponentType<any>> = {
    domain: BuildingOfficeIcon,
    ou: ServerIcon,
    group: UserGroupIcon,
    device: ComputerDesktopIcon,
    user: UserGroupIcon,
  };
  const Icon = icons[type] || ServerIcon;
  return <Icon className="w-5 h-5 text-gray-400" />;
}

// --- Deployment Status Badge ---
function DeploymentStatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string; label: string }> = {
    pending:   { bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Ausstehend' },
    running:   { bg: 'bg-blue-100',   text: 'text-blue-700',   label: 'Läuft' },
    completed: { bg: 'bg-green-100',  text: 'text-green-700',  label: 'Abgeschlossen' },
    failed:    { bg: 'bg-red-100',    text: 'text-red-700',    label: 'Fehlgeschlagen' },
    cancelled: { bg: 'bg-gray-100',   text: 'text-gray-600',   label: 'Abgebrochen' },
  };
  const c = config[status] || { bg: 'bg-gray-100', text: 'text-gray-600', label: status };
  return (
    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${c.bg} ${c.text}`}>
      {c.label}
    </span>
  );
}

// --- Deploy Modal ---
function DeployModal({
  app,
  onClose,
  onDeployed,
}: {
  app: { id: string; display_name?: string; name: string; version: string };
  onClose: () => void;
  onDeployed: () => void;
}) {
  const [targetType, setTargetType] = useState<'all' | 'group' | 'device' | 'user'>('all');
  const [targetId, setTargetId] = useState('');
  const [mandatory, setMandatory] = useState(false);
  const [deadline, setDeadline] = useState('');
  const [deploying, setDeploying] = useState(false);

  const DEMO_GROUPS = [
    { id: 'all-devices', name: 'Alle Geräte' },
    { id: 'macos-devices', name: 'macOS Geräte' },
    { id: 'windows-devices', name: 'Windows Geräte' },
    { id: 'it-department', name: 'IT-Abteilung' },
    { id: 'marketing', name: 'Marketing' },
    { id: 'finance', name: 'Finanzen' },
  ];

  const buildTargets = () => {
    if (targetType === 'all') {
      return [{ type: 'group' as const, id: 'all-devices', name: 'Alle Geräte' }];
    }
    if (!targetId.trim()) return null;
    return [{ type: targetType, id: targetId.trim(), name: targetId.trim() }];
  };

  const handleDeploy = async () => {
    const targets = buildTargets();
    if (!targets) { return; }
    setDeploying(true);
    try {
      const res = await fetch(`/api/appstore/apps/${app.id}/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets,
          mandatory,
          deadline: deadline || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Deployment fehlgeschlagen');
      }
      onDeployed();
    } catch (err: any) {
      alert(err.message || 'Deployment fehlgeschlagen');
    } finally {
      setDeploying(false);
    }
  };

  const isValid = targetType === 'all' || targetId.trim().length > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <RocketLaunchIcon className="h-5 w-5 text-violet-600" />
            <h2 className="text-base font-semibold text-gray-900">App deployen</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-5">
          {/* App info */}
          <div className="flex items-center gap-3 bg-violet-50 rounded-lg p-3">
            <RocketLaunchIcon className="h-8 w-8 text-violet-500 flex-shrink-0" />
            <div>
              <p className="text-sm font-semibold text-gray-900">{app.display_name || app.name}</p>
              <p className="text-xs text-gray-500">v{app.version}</p>
            </div>
          </div>

          {/* Target selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Zielgruppe</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { value: 'all', label: 'Alle Geräte' },
                { value: 'group', label: 'Bestimmte Gruppe' },
                { value: 'device', label: 'Bestimmte Geräte' },
                { value: 'user', label: 'Bestimmte Benutzer' },
              ].map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => { setTargetType(opt.value as any); setTargetId(''); }}
                  className={`py-2 px-3 rounded-lg border text-sm font-medium transition-colors text-left ${
                    targetType === opt.value
                      ? 'border-violet-500 bg-violet-50 text-violet-700'
                      : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Group/Device/User picker */}
          {targetType === 'group' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Gruppe auswählen</label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-violet-500"
              >
                <option value="">— Gruppe wählen —</option>
                {DEMO_GROUPS.slice(1).map((g) => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
            </div>
          )}
          {(targetType === 'device' || targetType === 'user') && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {targetType === 'device' ? 'Geräte-ID' : 'Benutzer-ID'} eingeben
              </label>
              <input
                type="text"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder={targetType === 'device' ? 'z.B. LAPTOP-001' : 'z.B. max.muster@corp.local'}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-violet-500"
              />
            </div>
          )}

          {/* Mandatory toggle */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-700">Pflichtinstallation</p>
              <p className="text-xs text-gray-500">App wird automatisch auf Zielgeräten installiert</p>
            </div>
            <button
              onClick={() => setMandatory(!mandatory)}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                mandatory ? 'bg-violet-600' : 'bg-gray-200'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform transition-transform duration-200 ease-in-out ${
                  mandatory ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Deadline */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Deadline <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              type="datetime-local"
              value={deadline}
              onChange={(e) => setDeadline(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-violet-500"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-xl">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-800">
            Abbrechen
          </button>
          <button
            onClick={handleDeploy}
            disabled={!isValid || deploying}
            className="flex items-center gap-1.5 bg-violet-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-violet-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {deploying ? (
              <>
                <ArrowPathIcon className="h-4 w-4 animate-spin" />
                <span>Wird deployed…</span>
              </>
            ) : (
              <>
                <RocketLaunchIcon className="h-4 w-4" />
                <span>Jetzt deployen</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Share App Modal ---

interface ScannedFile {
  name: string;
  relativePath: string;
  platforms: string[];
  suggestedName: string;
}

function ShareAppModal({
  categories,
  onClose,
  onSaved,
}: {
  categories: StoreCategory[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [shares, setShares] = useState<{ id: string; name: string; server: string; path: string; protocol: string }[]>([]);
  const [selectedShareId, setSelectedShareId] = useState('');
  const [scanning, setScanning]   = useState(false);
  const [scanError, setScanError] = useState('');
  const [files, setFiles]         = useState<ScannedFile[]>([]);
  const [selected, setSelected]   = useState<Set<string>>(new Set());
  const [saving, setSaving]       = useState(false);
  // per-file metadata overrides
  const [meta, setMeta] = useState<Record<string, { display_name: string; version: string; category: string }>>({});

  useEffect(() => {
    fetch('/api/network/shares')
      .then(r => r.ok ? r.json() : { shares: [] })
      .then(d => setShares((d.shares || []).filter((s: any) => s.purpose?.includes('apps'))))
      .catch(() => {});
  }, []);

  const handleScan = async () => {
    if (!selectedShareId) return;
    setScanning(true); setScanError(''); setFiles([]); setSelected(new Set());
    try {
      const res = await appStoreApi.scanShare(selectedShareId);
      const found: ScannedFile[] = res.data.files || [];
      setFiles(found);
      // pre-select all, init meta
      setSelected(new Set(found.map(f => f.relativePath)));
      const initMeta: typeof meta = {};
      for (const f of found) {
        initMeta[f.relativePath] = { display_name: f.suggestedName, version: '1.0.0', category: categories[0]?.name || 'utilities' };
      }
      setMeta(initMeta);
      if (res.data.error) setScanError(res.data.error);
    } catch (err: any) {
      setScanError(err?.response?.data?.error || 'Scan fehlgeschlagen');
    } finally {
      setScanning(false);
    }
  };

  const toggleFile = (path: string) =>
    setSelected(s => { const n = new Set(s); n.has(path) ? n.delete(path) : n.add(path); return n; });

  const updateMeta = (path: string, field: string, value: string) =>
    setMeta(m => ({ ...m, [path]: { ...m[path], [field]: value } }));

  const handleImport = async () => {
    const toImport = files.filter(f => selected.has(f.relativePath));
    if (toImport.length === 0) { toast.error('Mind. eine Datei auswählen'); return; }
    setSaving(true);
    let count = 0;
    for (const f of toImport) {
      const m = meta[f.relativePath] || { display_name: f.suggestedName, version: '1.0.0', category: categories[0]?.name || 'utilities' };
      const name = m.display_name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
      const packages: Record<string, any> = {};
      for (const p of f.platforms) {
        packages[p] = { type: 'share', share_id: selectedShareId, path: f.relativePath };
      }
      try {
        await appStoreApi.createApp({
          name,
          display_name: m.display_name,
          version: m.version,
          category: m.category,
          platforms: f.platforms,
          packages,
          metadata: { source: 'share', share_id: selectedShareId, original_file: f.name },
        });
        count++;
      } catch {}
    }
    setSaving(false);
    toast.success(`${count} App${count !== 1 ? 's' : ''} importiert`);
    onSaved();
  };

  const selectedShare = shares.find(s => s.id === selectedShareId);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <ServerIcon className="h-5 w-5 text-purple-600" />
            <h2 className="text-base font-semibold text-gray-900">Apps aus File Share importieren</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><XMarkIcon className="h-5 w-5" /></button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

          {/* Share picker + scan button */}
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-700 mb-1">
                File Share <span className="text-gray-400">(nur «Apps»-Shares)</span>
              </label>
              {shares.length === 0 ? (
                <div className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                  Kein Share mit Zweck «App-Verteilung» gefunden. Unter Infrastruktur → File Shares einen Share als «Apps» markieren.
                </div>
              ) : (
                <select
                  value={selectedShareId}
                  onChange={e => { setSelectedShareId(e.target.value); setFiles([]); setScanError(''); }}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500"
                >
                  <option value="">— Share auswählen —</option>
                  {shares.map(s => <option key={s.id} value={s.id}>{s.name} ({s.protocol} · {s.server})</option>)}
                </select>
              )}
            </div>
            <button
              onClick={handleScan}
              disabled={!selectedShareId || scanning}
              className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700 disabled:opacity-40 whitespace-nowrap"
            >
              {scanning ? <ArrowPathIcon className="h-4 w-4 animate-spin" /> : <MagnifyingGlassIcon className="h-4 w-4" />}
              {scanning ? 'Scanne…' : 'Share scannen'}
            </button>
          </div>

          {selectedShare && (
            <p className="text-xs text-gray-400 font-mono">
              {selectedShare.protocol === 'SMB' ? `\\\\${selectedShare.server}\\${selectedShare.path}` : `${selectedShare.server}:${selectedShare.path}`}
            </p>
          )}

          {scanError && (
            <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
              {scanError}
            </div>
          )}

          {/* Found files */}
          {files.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-medium text-gray-700">{files.length} Installer gefunden — auswählen zum Importieren</p>
                <div className="flex gap-2">
                  <button onClick={() => setSelected(new Set(files.map(f => f.relativePath)))} className="text-xs text-purple-600 hover:underline">Alle</button>
                  <button onClick={() => setSelected(new Set())} className="text-xs text-gray-400 hover:underline">Keine</button>
                </div>
              </div>
              <div className="space-y-2">
                {files.map(f => {
                  const sel = selected.has(f.relativePath);
                  const m = meta[f.relativePath] || { display_name: f.suggestedName, version: '1.0.0', category: categories[0]?.name || 'utilities' };
                  return (
                    <div key={f.relativePath} className={`border rounded-lg p-3 transition-colors ${sel ? 'border-purple-300 bg-purple-50' : 'border-gray-200 bg-gray-50'}`}>
                      <div className="flex items-start gap-2">
                        <button
                          onClick={() => toggleFile(f.relativePath)}
                          className={`w-4 h-4 rounded mt-0.5 flex-shrink-0 flex items-center justify-center ${sel ? 'bg-purple-600' : 'border border-gray-300 bg-white'}`}
                        >
                          {sel && <CheckCircleIcon className="h-3 w-3 text-white" />}
                        </button>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-mono text-gray-600 truncate">{f.relativePath}</p>
                          <div className="flex gap-1 mt-1">
                            {f.platforms.map(p => (
                              <span key={p} className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${p === 'windows' ? 'bg-blue-100 text-blue-700' : p === 'macos' ? 'bg-gray-100 text-gray-700' : 'bg-orange-100 text-orange-700'}`}>{p}</span>
                            ))}
                          </div>
                          {sel && (
                            <div className="grid grid-cols-3 gap-2 mt-2">
                              <div className="col-span-1">
                                <input
                                  value={m.display_name}
                                  onChange={e => updateMeta(f.relativePath, 'display_name', e.target.value)}
                                  placeholder="App-Name"
                                  className="w-full border border-gray-200 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-purple-400 bg-white"
                                />
                              </div>
                              <div>
                                <input
                                  value={m.version}
                                  onChange={e => updateMeta(f.relativePath, 'version', e.target.value)}
                                  placeholder="Version"
                                  className="w-full border border-gray-200 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-purple-400 bg-white"
                                />
                              </div>
                              <div>
                                <select
                                  value={m.category}
                                  onChange={e => updateMeta(f.relativePath, 'category', e.target.value)}
                                  className="w-full border border-gray-200 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-purple-400 bg-white"
                                >
                                  {categories.map(c => <option key={c.id} value={c.name}>{c.display_name}</option>)}
                                </select>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {!scanning && files.length === 0 && selectedShareId && !scanError && (
            <p className="text-xs text-gray-400 text-center py-4">Share scannen um Installer-Dateien zu finden</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-xl">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-800">Abbrechen</button>
          <button
            onClick={handleImport}
            disabled={saving || selected.size === 0}
            className="flex items-center gap-1.5 bg-purple-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-purple-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {saving ? 'Importiere…' : `${selected.size} App${selected.size !== 1 ? 's' : ''} importieren`}
            {!saving && <ChevronRightIcon className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </div>
  );
}
