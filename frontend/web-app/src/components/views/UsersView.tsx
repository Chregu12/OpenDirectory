'use client';

import React, { useState } from 'react';
import ABMShell from '@/components/layout/ABMShell';
import UserListColumn, { DirectoryUser } from './UserListColumn';
import UserDetailPanel from './UserDetailPanel';

interface UsersViewProps {
  onCreateNew?: () => void;
}

export default function UsersView({ onCreateNew }: UsersViewProps) {
  const [selectedUser, setSelectedUser] = useState<DirectoryUser | null>(null);

  return (
    <ABMShell
      showListColumn
      listColumn={
        <UserListColumn
          selectedId={selectedUser?.id ?? null}
          onSelect={setSelectedUser}
          onCreateNew={onCreateNew}
        />
      }
      detailPanel={
        <UserDetailPanel user={selectedUser} onClose={() => setSelectedUser(null)} />
      }
    />
  );
}
