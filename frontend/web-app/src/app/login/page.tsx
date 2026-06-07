'use client';

import React, { useState } from 'react';
import { startLogin } from '@/lib/auth';

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSignIn = async () => {
    setError('');
    setLoading(true);
    try {
      await startLogin();
      // startLogin() redirects the browser — execution will not continue here
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to start login';
      setError(message);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center mb-4 shadow-md">
            <span className="text-white font-bold text-lg">OD</span>
          </div>
          <h1 className="text-2xl font-semibold text-gray-900">OpenDirectory</h1>
          <p className="text-sm text-gray-500 mt-1">Sign in to your account</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-3 py-2 mb-5">
              {error}
            </div>
          )}

          <button
            onClick={handleSignIn}
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Redirecting…' : 'Sign in with OpenDirectory'}
          </button>
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          OpenDirectory
        </p>
      </div>
    </div>
  );
}
