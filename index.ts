import {
  ChannelCredentials,
  Metadata,
  ServiceError,
  credentials,
  loadPackageDefinition,
} from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";

type MetadataItem = { key: string; value: string | number | boolean };

type HealthCheckInput = {
  /**
   * Target gRPC address in the form of host:port.
   * `target` is preferred but `host` is also accepted for compatibility.
   */
  target?: string;
  host?: string;
  service?: string;
  /**
   * Set to true to use an insecure channel (plain TCP).
   * Defaults to TLS.
   */
  insecure?: boolean;
  metadata?: MetadataItem[];
};

type HealthCheckResult = {
  status: string;
  rawStatus: string | number | undefined;
  serving: boolean;
  response: unknown;
};

type HealthClientConstructor = new (
  address: string,
  creds: ChannelCredentials
) => {
  Check(
    request: { service?: string },
    md: Metadata,
    callback: (err: ServiceError | null, response: { status?: string | number }) => void
  ): void;
  close(): void;
};

type HealthProto = {
  grpc: { health: { v1: { Health: HealthClientConstructor } } };
};

const HEALTH_PROTO_PATH = fileURLToPath(new URL("./health.proto", import.meta.url));

const packageDefinition = protoLoader.loadSync(HEALTH_PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const healthPackage = loadPackageDefinition(packageDefinition) as unknown as HealthProto;
const HealthClient = healthPackage.grpc.health.v1.Health;

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

function normalizeMetadata(metadata: unknown): MetadataItem[] {
  if (!Array.isArray(metadata)) return [];

  return metadata
    .map((entry) => (entry && typeof entry === "object" ? entry : null))
    .filter(
      (entry): entry is { key?: unknown; value?: unknown } =>
        !!entry && typeof entry.key === "string" && entry.value !== undefined
    )
    .map((entry) => ({
      key: entry.key as string,
      value: entry.value as string | number | boolean,
    }));
}

function applyClientKeyAuthorization(entries: MetadataItem[]): MetadataItem[] {
  const clientEntry = entries.find((entry) => entry.key.toLowerCase() === "client-key");
  if (!clientEntry) return entries;

  const secretKey = String(clientEntry.value);
  const seconds = Math.floor(Date.now() / 1000);
  const rounded = seconds - (seconds % 30); // 30-second step, similar to TOTP
  const signature = createHmac("sha256", secretKey).update(String(rounded)).digest("hex");

  // Remove client-key and any existing Authorization before adding new one
  const filtered = entries.filter(
    (entry) =>
      entry.key.toLowerCase() !== "client-key" && entry.key.toLowerCase() !== "authorization"
  );

  return [...filtered, { key: "Authorization", value: `TOTP ${signature}` }];
}

function buildGrpcMetadata(input: HealthCheckInput): { grpcMetadata: Metadata; sent: MetadataItem[] } {
  const normalized = normalizeMetadata(input.metadata);
  const processed = applyClientKeyAuthorization(normalized);

  const md = new Metadata();
  for (const entry of processed) {
    md.add(entry.key, String(entry.value));
  }

  return { grpcMetadata: md, sent: processed };
}

function statusToString(status: unknown): string {
  if (status === 1 || status === "SERVING") return "SERVING";
  if (status === 2 || status === "NOT_SERVING") return "NOT_SERVING";
  if (status === 3 || status === "SERVICE_UNKNOWN") return "SERVICE_UNKNOWN";
  return "UNKNOWN";
}

function isServing(status: unknown): boolean {
  return status === "SERVING" || status === 1;
}

async function performHealthCheck(
  input: HealthCheckInput,
  grpcMetadata: Metadata
): Promise<HealthCheckResult> {
  const target = input.target ?? input.host;

  if (!target || typeof target !== "string") {
    throw new Error("`target` (host:port) is required in the payload.");
  }

  const channelCredentials = input.insecure ? credentials.createInsecure() : credentials.createSsl();
  const client = new HealthClient(target, channelCredentials);

  return new Promise<HealthCheckResult>((resolve, reject) => {
    client.Check(
      { service: input.service ?? "" },
      grpcMetadata,
      (err: ServiceError | null, response: { status?: string | number }) => {
        client.close();

        if (err) {
          reject(err);
          return;
        }

        const rawStatus = response?.status;
        const status = statusToString(rawStatus);

        resolve({
          status,
          rawStatus,
          serving: isServing(rawStatus),
          response,
        });
      }
    );
  });
}

function jsonResponse(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json", ...corsHeaders },
  });
}

const resolvedPort = (() => {
  if (process.env.PORT === undefined) return 3000;
  const parsed = Number(process.env.PORT);
  return Number.isFinite(parsed) ? parsed : 3000;
})();

const server = Bun.serve({
  port: resolvedPort,
  fetch: async (req) => {
    const { pathname } = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (pathname === "/" && req.method === "GET") {
      return jsonResponse(200, {
        message: "gRPC health passthrough is running.",
        endpoint: "POST /health/check",
        payloadExample: {
          target: "user.dev.v2.nobi.id:443",
          service: "",
          insecure: false,
          metadata: [{ key: "Authorization", value: "Bearer token" }],
        },
      });
    }

    if (pathname === "/health/check" && req.method === "POST") {
      let payload: HealthCheckInput | null = null;
      let metadataSent: MetadataItem[] | undefined;

      try {
        payload = await req.json();
      } catch (error) {
        return jsonResponse(400, {
          error: "Invalid JSON payload.",
          details: (error as Error).message,
        });
      }

      try {
        const { grpcMetadata, sent } = buildGrpcMetadata(payload);
        metadataSent = sent;
        const result = await performHealthCheck(payload, grpcMetadata);

        return jsonResponse(result.serving ? 200 : 503, {
          target: payload.target ?? payload.host,
          service: payload.service ?? "",
          insecure: !!payload.insecure,
          metadataSent: sent,
          status: result.status,
          rawStatus: result.rawStatus,
          serving: result.serving,
          grpcResponse: result.response,
        });
      } catch (error) {
        const serviceError = error as ServiceError;
        const errorMetadata =
          serviceError?.metadata && "getMap" in serviceError.metadata
            ? (serviceError.metadata as Metadata).getMap()
            : undefined;

        return jsonResponse(502, {
          error: serviceError?.message ?? "Health check failed.",
          code: serviceError?.code,
          details: serviceError?.details,
          metadata: errorMetadata,
          target: payload?.target ?? payload?.host,
          service: payload?.service ?? "",
          metadataSent,
        });
      }
    }

    return jsonResponse(404, { error: "Not Found" });
  },
});

console.log(`gRPC health passthrough listening on http://localhost:${server.port}`);
