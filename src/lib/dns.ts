// Bridge to the native BulwarkDns module. Exposes a single `resolveSrv`
// surface that mirrors what Node's `dns.resolveSrv` would return — JMAP
// auto-discovery (`_jmap._tcp.<domain>`) is the one consumer.
//
// On non-Android platforms (or if the device is too old to expose
// `android.net.DnsResolver`), the helper rejects with DnsUnsupportedError
// so callers can surface a meaningful fallback path.

type Native = {
  resolveSrv(name: string): Promise<SrvRecord[]>;
};

export interface SrvRecord {
  priority: number;
  weight: number;
  port: number;
  target: string;
}

export class DnsUnsupportedError extends Error {
  constructor() {
    super('DNS SRV lookup is not available on this platform');
  }
}

export class DnsLookupError extends Error {}

let nativeProbed = false;
let nativeModule: Native | null = null;

function getNative(): Native | null {
  if (nativeProbed) return nativeModule;
  nativeProbed = true;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const rn = require('react-native') as {
      Platform: { OS: string };
      NativeModules: Record<string, unknown>;
    };
    if (rn.Platform.OS !== 'android') return (nativeModule = null);
    nativeModule = (rn.NativeModules.BulwarkDns as Native | undefined) ?? null;
  } catch {
    nativeModule = null;
  }
  return nativeModule;
}

export function isDnsSupported(): boolean {
  return getNative() != null;
}

// RFC 2782 ordering: ascending priority, then a weighted random shuffle
// inside each priority bucket. With a single record per priority this
// degenerates to the obvious thing.
export function pickSrvTarget(records: SrvRecord[]): SrvRecord | null {
  if (records.length === 0) return null;
  const byPriority = [...records].sort((a, b) => a.priority - b.priority);
  const topPriority = byPriority[0].priority;
  const bucket = byPriority.filter((r) => r.priority === topPriority);
  if (bucket.length === 1) return bucket[0];
  const totalWeight = bucket.reduce((acc, r) => acc + Math.max(0, r.weight), 0);
  if (totalWeight === 0) return bucket[0];
  let pick = Math.floor(Math.random() * totalWeight);
  for (const r of bucket) {
    pick -= Math.max(0, r.weight);
    if (pick < 0) return r;
  }
  return bucket[bucket.length - 1];
}

export async function resolveSrv(name: string): Promise<SrvRecord[]> {
  const native = getNative();
  if (!native) throw new DnsUnsupportedError();
  try {
    return await native.resolveSrv(name);
  } catch (err) {
    if (err instanceof Error) throw new DnsLookupError(err.message);
    throw new DnsLookupError('DNS lookup failed');
  }
}
