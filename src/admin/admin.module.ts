import { Global, Module } from "@nestjs/common";
import { AdminGuard } from "./admin.guard";
import { AdminAuditService } from "./admin-audit.service";
import { EgressHealthController } from "./egress-health.controller";
import { AdminConfigController } from "./admin-config.controller";

/** Admin RBAC guard and audit trail shared by jobs, flags, kill-switch and governance. */
@Global()
@Module({
  controllers: [EgressHealthController, AdminConfigController],
  providers: [AdminGuard, AdminAuditService],
  exports: [AdminGuard, AdminAuditService],
})
export class AdminModule {}