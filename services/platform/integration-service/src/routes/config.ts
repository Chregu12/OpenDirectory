import { Router } from "express";
import { requireAdmin } from "../middleware/oidcAuth";
import { ModuleStore, moduleDefaults } from "../services/module-store";
import { SERVICES, isServiceEnabled } from "../config/services";
const router = Router();
const modules = new ModuleStore();
router.get("/modules", async (_req, res) => {
  try {
    res.set("Cache-Control", "no-store").json(await modules.list());
  } catch {
    res.status(503).json({ error: "Module configuration storage unavailable" });
  }
});
router.get("/modules/:moduleId", async (req, res) => {
  if (
    !Object.prototype.hasOwnProperty.call(moduleDefaults, req.params.moduleId)
  )
    return res.status(404).json({ error: "Module not found" });
  try {
    res.json((await modules.list())[req.params.moduleId]);
  } catch {
    res.status(503).json({ error: "Module configuration storage unavailable" });
  }
});
router.post("/modules/:moduleId", requireAdmin, async (req, res) => {
  const id = req.params.moduleId;
  if (!Object.prototype.hasOwnProperty.call(moduleDefaults, id))
    return res.status(404).json({ error: "Module not found" });
  if (
    typeof req.body.enabled !== "boolean" ||
    Object.keys(req.body).some((key) => key !== "enabled")
  )
    return res
      .status(400)
      .json({ error: "An explicit enabled boolean is required" });
  try {
    res.json(await modules.update(id, req.body.enabled));
  } catch {
    res.status(503).json({ error: "Module configuration not confirmed" });
  }
});
router.get("/features", (_req, res) => {
  const enabled = Object.keys(SERVICES).filter(isServiceEnabled);
  res.json({
    lldapIntegration: enabled.includes("lldap"),
    grafanaDashboards: enabled.includes("grafana"),
    prometheusMetrics: enabled.includes("prometheus"),
    vaultSecrets: enabled.includes("vault"),
    deviceEnrollment: false,
  });
});
router.get("/settings", (_req, res) =>
  res.json({
    siteName: "OpenDirectory",
    language: "de",
    theme: "browser-preference",
    configurationStorage: "postgresql",
  }),
);
export default router;
