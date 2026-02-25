'use client';

import React, { useState } from 'react';
import UnifiLayout from '@/components/layout/UnifiLayout';
import DashboardView from '@/components/views/DashboardView';
import TopologyView from '@/components/views/TopologyView';
import ApplicationsView from '@/components/views/ApplicationsView';
import ServicesDashboard from '@/components/dashboard/ServicesDashboard';

// Placeholder components for other views
const DevicesView = () => (
  <div className="p-6">
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-8 text-center">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Device Management</h2>
      <p className="text-gray-600 mb-6">Comprehensive device management interface coming soon</p>
      <div className="bg-blue-50 p-4 rounded-lg">
        <p className="text-sm text-blue-700">
          This view will show all managed devices, enrollment status, compliance information, 
          and allow bulk operations on device collections.
        </p>
      </div>
    </div>
  </div>
);

const MonitoringView = () => (
  <div className="p-6">
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-8 text-center">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Insights & Analytics</h2>
      <p className="text-gray-600 mb-6">Advanced monitoring and analytics dashboard</p>
      <div className="bg-green-50 p-4 rounded-lg">
        <p className="text-sm text-green-700">
          Real-time metrics, performance graphs, usage analytics, and predictive insights 
          will be available in this comprehensive monitoring interface.
        </p>
      </div>
    </div>
  </div>
);

const SettingsView = () => (
  <div className="p-6">
    <ServicesDashboard />
  </div>
);

export default function UnifiApp() {
  const [activeView, setActiveView] = useState('dashboard');

  const renderActiveView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView />;
      case 'topology':
        return <TopologyView />;
      case 'devices':
        return <DevicesView />;
      case 'applications':
        return <ApplicationsView />;
      case 'monitoring':
        return <MonitoringView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <UnifiLayout activeView={activeView} onViewChange={setActiveView}>
      {renderActiveView()}
    </UnifiLayout>
  );
}