export interface KpiEvent {
  kpiId: string;
  value: number;
  unit: 'ms' | 'bytes' | 'boolean';
  timestamp: number;
  sessionId: string;
  executionContext: {
    cryptoMode: 'true';
    hostClass: 'desktop' | 'mobile-emulation' | 'target-edge';
    networkMode: 'none' | 'emulated';
  };
  context?: Record<string, string | number | boolean>;
}

class KpiTelemetryService {
  private events: KpiEvent[] = [];
  private sessionId: string;
  private isEnabled: boolean = true;

  constructor() {
    this.sessionId = crypto.randomUUID();
    // Allow disabling via environment variable or feature flag
    this.isEnabled = (typeof process !== 'undefined' ? process.env.VITE_ENABLE_KPI_TELEMETRY : (import.meta as any).env?.VITE_ENABLE_KPI_TELEMETRY) !== 'false';
  }

  public record(
    kpiId: string,
    value: number,
    unit: 'ms' | 'bytes' | 'boolean',
    context?: Record<string, string | number | boolean>
  ): void {
    if (!this.isEnabled) return;

    const event: KpiEvent = {
      kpiId,
      value,
      unit,
      timestamp: Date.now(),
      sessionId: this.sessionId,
      executionContext: {
        cryptoMode: 'true',
        // In a real environment, we might detect this dynamically. Assuming desktop for now.
        hostClass: 'desktop', 
        networkMode: 'none',
      },
      context,
    };

    this.events.push(event);
    console.debug(`[KPI] ${kpiId}: ${value} ${unit}`, event);
  }

  public getSnapshot(): KpiEvent[] {
    return [...this.events];
  }

  public exportSnapshotAsJson(): string {
    return JSON.stringify(this.getSnapshot(), null, 2);
  }

  public clear(): void {
    this.events = [];
  }

  public disable(): void {
    this.isEnabled = false;
  }

  public enable(): void {
    this.isEnabled = true;
  }
}

export const KpiTelemetry = new KpiTelemetryService();
