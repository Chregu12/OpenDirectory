"use client";
import DeviceInventoryView from "./DeviceInventoryView";
export default function AssignmentView() {
  return (
    <div className="space-y-6">
      <div className="od-panel space-y-3">
        <p>
          Gerätezuweisungen werden im bestätigten eigenen Inventar verwaltet.
          Lizenzquellen und Rückgaben haben getrennte Abläufe.
        </p>
        <div className="flex flex-wrap gap-3">
          <a className="fluent-btn-secondary" href="/licenses">
            Lizenzzuweisungen
          </a>
          <a className="fluent-btn-secondary" href="/device-returns">
            Geräterückgaben
          </a>
        </div>
      </div>
      <DeviceInventoryView />
    </div>
  );
}
