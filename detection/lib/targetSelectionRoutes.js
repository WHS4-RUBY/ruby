"use strict";

const { checkTargetReachable } = require("./targetSelection");

function installTargetSelectionRoutes({ app, targetSelection, probe = checkTargetReachable }) {
  // installDashboardRoutes must run first: it applies the dashboard session
  // guard to the whole /__detection/api namespace.
  app.get("/__detection/api/target-selection", (_req, res) => {
    try { res.json(targetSelection.publicStatus()); }
    catch { res.status(503).json({ error: "target selection state unavailable" }); }
  });

  app.post("/__detection/api/target-selection", async (req, res) => {
    const expectedOrigin = `${req.protocol}://${req.get("host")}`;
    if (req.get("Origin") !== expectedOrigin ||
        req.get("X-Ruby-Target-Selection") !== "1") {
      return res.status(403).json({ error: "same-origin target selection required" });
    }
    const targetId = req.body?.targetId;
    if (typeof targetId !== "string" || !targetSelection.choices.has(targetId)) {
      return res.status(400).json({ error: "unknown target ID" });
    }
    try {
      await probe(targetSelection.choices.get(targetId));
    } catch {
      return res.status(503).json({ error: "target is not reachable" });
    }
    try {
      const active = targetSelection.select(targetId);
      console.info(`[target-selection] ${active.targetId} run=${active.runId}`);
      return res.json(targetSelection.publicStatus());
    } catch {
      return res.status(503).json({ error: "target selection state unavailable" });
    }
  });
}

module.exports = { installTargetSelectionRoutes };
