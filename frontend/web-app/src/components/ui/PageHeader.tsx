"use client";
import type { ComponentType, ReactNode, SVGProps } from "react";
import { Squares2X2Icon } from "@heroicons/react/24/outline";

export function PageHeader({
  title,
  subtitle,
  icon: Icon = Squares2X2Icon,
  actions,
}: {
  title: string;
  subtitle?: string;
  icon?: ComponentType<SVGProps<SVGSVGElement>>;
  actions?: ReactNode;
}) {
  return (
    <header className="od-page-header">
      <div className="flex items-center gap-3 min-w-0">
        <span className="od-page-icon" aria-hidden="true">
          <Icon className="h-6 w-6" />
        </span>
        <div className="min-w-0">
          <h1>{title}</h1>
          {subtitle && <p>{subtitle}</p>}
        </div>
      </div>
      {actions && (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      )}
    </header>
  );
}
