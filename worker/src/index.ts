import type { WorkerEnv } from "./bindings";
import { handleWorkerFetch, handleWorkerScheduled } from "./runtime";

export { FleetDurableObject } from "./state/durable";

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async scheduled(event: ScheduledController, env: WorkerEnv): Promise<void> {
    await handleWorkerScheduled(event, env);
  },
} satisfies ExportedHandler<WorkerEnv>;
