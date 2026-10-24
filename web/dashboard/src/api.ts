import type { Pin, ScanRecord, Summary } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function getJSON<T>(path: string): Promise<T> {
  const resp = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!resp.ok) {
    let msg = `request failed (${resp.status})`;
    try {
      const body = (await resp.json()) as { error?: string };
      if (body.error) msg = body.error;
    } catch {
      /* keep the generic message */
    }
    throw new ApiError(msg, resp.status);
  }
  return (await resp.json()) as T;
}

export const listScans = (days: number) =>
  getJSON<{ scans: Summary[]; skipped: number }>(`/api/scans?days=${days}&limit=5000`);

export const getScan = (id: string) => getJSON<ScanRecord>(`/api/scans/${encodeURIComponent(id)}`);

export const latestPins = () => getJSON<{ records: (ScanRecord & { pins: Pin[] })[] }>("/api/pins/latest");
