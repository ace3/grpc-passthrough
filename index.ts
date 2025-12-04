import {
  ChannelCredentials,
  Client,
  Metadata,
  credentials,
  makeGenericClientConstructor,
} from "@grpc/grpc-js";

import type { ServiceError } from "@grpc/grpc-js";
import { createHmac } from "node:crypto";

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

// Define the Health service using generic client constructor
// This approach is more lenient with response parsing
const HealthServiceDefinition = {
  Check: {
    path: "/grpc.health.v1.Health/Check",
    requestStream: false,
    responseStream: false,
    requestSerialize: (request: { service?: string }) => {
      // Manually serialize the request (simple proto encoding)
      const service = request.service ?? "";
      if (service.length === 0) {
        return Buffer.alloc(0);
      }
      // Field 1, wire type 2 (length-delimited) = 0x0a
      const serviceBytes = Buffer.from(service, "utf8");
      const header = Buffer.from([0x0a, serviceBytes.length]);
      return Buffer.concat([header, serviceBytes]);
    },
    requestDeserialize: (buffer: Buffer) => {
      return { service: buffer.toString("utf8") };
    },
    responseSerialize: (response: unknown) => {
      return Buffer.from(JSON.stringify(response));
    },
    responseDeserialize: (buffer: Buffer): Record<string, unknown> => {
      // Parse protobuf response manually to handle non-standard responses
      return parseProtobufResponse(buffer);
    },
  },
};

/**
 * Manually parse a protobuf response buffer.
 * This is lenient and handles unknown fields gracefully.
 */
function parseProtobufResponse(buffer: Buffer): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let offset = 0;

  while (offset < buffer.length) {
    const tag = buffer[offset];
    if (tag === undefined) break;

    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;
    offset++;

    switch (wireType) {
      case 0: {
        // Varint
        let value = 0;
        let shift = 0;
        while (offset < buffer.length) {
          const byte = buffer[offset];
          if (byte === undefined) break;
          offset++;
          value |= (byte & 0x7f) << shift;
          if ((byte & 0x80) === 0) break;
          shift += 7;
        }
        result[`field_${fieldNumber}`] = value;
        // Map known fields
        if (fieldNumber === 1) {
          result.status = value;
        }
        break;
      }
      case 2: {
        // Length-delimited (string, bytes, embedded message)
        let length = 0;
        let shift = 0;
        while (offset < buffer.length) {
          const byte = buffer[offset];
          if (byte === undefined) break;
          offset++;
          length |= (byte & 0x7f) << shift;
          if ((byte & 0x80) === 0) break;
          shift += 7;
        }
        const data = buffer.subarray(offset, offset + length);
        offset += length;

        // Try to decode as UTF-8 string
        try {
          const str = data.toString("utf8");
          result[`field_${fieldNumber}`] = str;
          // Map known fields based on observed server responses
          if (fieldNumber === 2) result.latency = str;
          if (fieldNumber === 4) result.error_code = str;
          if (fieldNumber === 5) result.error_message = str;
        } catch {
          result[`field_${fieldNumber}`] = data;
        }
        break;
      }
      default:
        // Skip unknown wire types
        console.warn(`Unknown wire type ${wireType} at offset ${offset - 1}`);
        // Try to skip - this is a best effort
        offset = buffer.length; // Exit loop for safety
        break;
    }
  }

  return result;
}

type HealthClient = Client & {
  Check(
    request: { service?: string },
    metadata: Metadata,
    callback: (err: ServiceError | null, response: Record<string, unknown>) => void
  ): void;
};

const GenericHealthClient = makeGenericClientConstructor(
  HealthServiceDefinition,
  "grpc.health.v1.Health"
) as unknown as new (address: string, creds: ChannelCredentials) => HealthClient;

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
  const client = new GenericHealthClient(target, channelCredentials);

  return new Promise<HealthCheckResult>((resolve, reject) => {
    client.Check(
      { service: input.service ?? "" },
      grpcMetadata,
      (err: ServiceError | null, response: Record<string, unknown>) => {
        client.close();

        if (err) {
          reject(err);
          return;
        }

        const rawStatus = response?.status as string | number | undefined;
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
      let payload: HealthCheckInput;
      let metadataSent: MetadataItem[] | undefined;

      try {
        payload = await req.json() as HealthCheckInput;
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

        // Determine HTTP status based on gRPC error code
        // Code 16 = UNAUTHENTICATED
        // Code 7 = PERMISSION_DENIED
        // Code 13 with parsing error = likely auth rejection returning non-gRPC response
        const isAuthError =
          serviceError?.code === 16 ||
          serviceError?.code === 7 ||
          (serviceError?.code === 13 &&
            serviceError?.details?.includes("Response message parsing error"));
        const httpStatus = isAuthError ? 401 : 502;

        return jsonResponse(httpStatus, {
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
