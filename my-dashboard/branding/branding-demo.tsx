import { useState, useEffect, createContext, useContext, type ReactNode } from "react";

// ============================================================
// TYPES
// ============================================================
interface ColorScale {
  100: string;
  200: string;
  300: string;
  400: string;
  500: string;
  600: string;
  700: string;
  800: string;
  900: string;
  1000: string;
}

interface GlobalColors {
  critical: ColorScale;
  brandSecondary: ColorScale;
  success: ColorScale;
  neutral: ColorScale;
  warning: ColorScale;
  informative: ColorScale;
  brand: ColorScale;
}

interface BrandingTheme {
  logos: { dark: string; light: string };
  fonts: { primary: string };
  colors: { global: GlobalColors };
}

interface BrandingConfig {
  generalSettings: {
    minPaymentAmountUsd: number;
    maxPaymentAmountUsd: number;
  };
  theme: BrandingTheme;
  partnerName: string;
  id: string;
}

interface AppConfig {
  apiBaseUrl: string;
  cdnUrl: string;
  branding: BrandingConfig | null;
}

interface BrandingContextValue {
  branding: BrandingConfig;
  loading: boolean;
  source: string;
  error: string | null;
}

type AlertType = "critical" | "success" | "warning" | "informative";
type ColorCategory = keyof GlobalColors;
type ButtonVariant = "primary" | "secondary" | "danger";

// CSS variable-safe category names (camelCase → kebab-case)
const COLOR_CSS_MAP: Record<ColorCategory, string> = {
  critical: "critical",
  brandSecondary: "brand-secondary",
  success: "success",
  neutral: "neutral",
  warning: "warning",
  informative: "informative",
  brand: "brand",
};

// ============================================================
// 1. DEFAULT THEME — baked into the app, never breaks
// ============================================================
const DEFAULT_THEME: BrandingConfig = {
  generalSettings: { minPaymentAmountUsd: 1, maxPaymentAmountUsd: 999999.99 },
  theme: {
    logos: { dark: "", light: "" },
    fonts: { primary: "system-ui, -apple-system, sans-serif" },
    colors: {
      global: {
        critical: {
          100: "#FDE7E9", 200: "#FAC4C9", 300: "#F9B4BA", 400: "#F79CA4",
          500: "#F57F89", 600: "#F14755", 700: "#D80E25", 800: "#C50C22",
          900: "#8D0411", 1000: "#6D030D",
        },
        brandSecondary: {
          100: "#E6F3FF", 200: "#D6EBFF", 300: "#C8E3F8", 400: "#A4D1F4",
          500: "#46A3EB", 600: "#096CB8", 700: "#00508D", 800: "#004880",
          900: "#004071", 1000: "#003359",
        },
        success: {
          100: "#DFF5E7", 200: "#B1E2C4", 300: "#9BDAB3", 400: "#7DCF9D",
          500: "#54BF7E", 600: "#41AE6C", 700: "#028838", 800: "#00702D",
          900: "#01481F", 1000: "#012811",
        },
        neutral: {
          100: "#FFFFFF", 200: "#F8FAFC", 300: "#F1F5F8", 400: "#E4E7EC",
          500: "#C3CAD5", 600: "#8B95A9", 700: "#646F87", 800: "#475467",
          900: "#344054", 1000: "#18191B",
        },
        warning: {
          100: "#FFF8E6", 200: "#FFF0CA", 300: "#FFE9B2", 400: "#FFE299",
          500: "#FFD875", 600: "#FDC535", 700: "#FDB702", 800: "#E6A702",
          900: "#B88501", 1000: "#986E01",
        },
        informative: {
          100: "#E6F0FE", 200: "#C7DAFD", 300: "#B5CEFC", 400: "#A2C1FB",
          500: "#8FB4FA", 600: "#5484F8", 700: "#306AF7", 800: "#2256D6",
          900: "#0351C0", 1000: "#023D91",
        },
        brand: {
          100: "#EBF6FF", 200: "#DBEDFB", 300: "#C8E3F8", 400: "#A4D1F4",
          500: "#46A3EB", 600: "#096CB8", 700: "#00508D", 800: "#004880",
          900: "#004071", 1000: "#003359",
        },
      },
    },
  },
  partnerName: "Default Partner",
  id: "default",
};

// ============================================================
// 2. MOCK API — simulates GET /api/config from Insights API
//    Replace mockFetchAppConfig with real fetch("/api/config")
// ============================================================
const MOCK_SPONSORS: Record<string, BrandingConfig> = {
  fiserv: {
    generalSettings: { minPaymentAmountUsd: 1, maxPaymentAmountUsd: 999999.99 },
    theme: {
      logos: {
        dark: "https://platform-static.meliopayments.com/assets/fiserv/FiservLogoDark.svg",
        light: "https://platform-static.meliopayments.com/assets/fiserv/FiservLogo.svg",
      },
      fonts: { primary: '"Univers For Fiserv", Roboto, Arial, sans-serif' },
      colors: {
        global: {
          critical: {
            100: "#FDE7E9", 200: "#FAC4C9", 300: "#F9B4BA", 400: "#F79CA4",
            500: "#F57F89", 600: "#F14755", 700: "#D80E25", 800: "#C50C22",
            900: "#8D0411", 1000: "#6D030D",
          },
          brandSecondary: {
            100: "#E6F3FF", 200: "#D6EBFF", 300: "#C8E3F8", 400: "#A4D1F4",
            500: "#46A3EB", 600: "#096CB8", 700: "#00508D", 800: "#004880",
            900: "#004071", 1000: "#003359",
          },
          success: {
            100: "#DFF5E7", 200: "#B1E2C4", 300: "#9BDAB3", 400: "#7DCF9D",
            500: "#54BF7E", 600: "#41AE6C", 700: "#028838", 800: "#00702D",
            900: "#01481F", 1000: "#012811",
          },
          neutral: {
            100: "#FFFFFF", 200: "#F8FAFC", 300: "#F1F5F8", 400: "#E4E7EC",
            500: "#C3CAD5", 600: "#8B95A9", 700: "#646F87", 800: "#475467",
            900: "#344054", 1000: "#18191B",
          },
          warning: {
            100: "#FFF8E6", 200: "#FFF0CA", 300: "#FFE9B2", 400: "#FFE299",
            500: "#FFD875", 600: "#FDC535", 700: "#FDB702", 800: "#E6A702",
            900: "#B88501", 1000: "#986E01",
          },
          informative: {
            100: "#E6F0FE", 200: "#C7DAFD", 300: "#B5CEFC", 400: "#A2C1FB",
            500: "#8FB4FA", 600: "#5484F8", 700: "#306AF7", 800: "#2256D6",
            900: "#0351C0", 1000: "#023D91",
          },
          brand: {
            100: "#EBF6FF", 200: "#DBEDFB", 300: "#C8E3F8", 400: "#A4D1F4",
            500: "#46A3EB", 600: "#096CB8", 700: "#00508D", 800: "#004880",
            900: "#004071", 1000: "#003359",
          },
        },
      },
    },
    partnerName: "fiserv_testbank-claritypr1234511",
    id: "af9793f5-648b-4bcd-b55d-8c634c0a6eec",
  },
  acmebank: {
    generalSettings: { minPaymentAmountUsd: 5, maxPaymentAmountUsd: 50000.0 },
    theme: {
      logos: { dark: "", light: "" },
      fonts: { primary: "Georgia, serif" },
      colors: {
        global: {
          critical: {
            100: "#FFF0F0", 200: "#FFD6D6", 300: "#FFB3B3", 400: "#FF8080",
            500: "#FF4D4D", 600: "#E63939", 700: "#CC2929", 800: "#991F1F",
            900: "#661414", 1000: "#330A0A",
          },
          brandSecondary: {
            100: "#F0FAF0", 200: "#D6F5D6", 300: "#A8E6A8", 400: "#7AD97A",
            500: "#4DCC4D", 600: "#339933", 700: "#267326", 800: "#1A4D1A",
            900: "#0D260D", 1000: "#071307",
          },
          success: {
            100: "#F0FAF0", 200: "#D6F5D6", 300: "#A8E6A8", 400: "#7AD97A",
            500: "#4DCC4D", 600: "#339933", 700: "#267326", 800: "#1A4D1A",
            900: "#0D260D", 1000: "#071307",
          },
          neutral: {
            100: "#FFFFFF", 200: "#F5F5F0", 300: "#E8E8E0", 400: "#D4D4C8",
            500: "#B0B0A0", 600: "#888878", 700: "#605850", 800: "#483830",
            900: "#302018", 1000: "#1A1008",
          },
          warning: {
            100: "#FFF8E6", 200: "#FFF0CA", 300: "#FFE9B2", 400: "#FFE299",
            500: "#FFD875", 600: "#FDC535", 700: "#FDB702", 800: "#E6A702",
            900: "#B88501", 1000: "#986E01",
          },
          informative: {
            100: "#E6F0FE", 200: "#C7DAFD", 300: "#B5CEFC", 400: "#A2C1FB",
            500: "#8FB4FA", 600: "#5484F8", 700: "#306AF7", 800: "#2256D6",
            900: "#0351C0", 1000: "#023D91",
          },
          brand: {
            100: "#F0FAF0", 200: "#D6F5D6", 300: "#A8E6A8", 400: "#7AD97A",
            500: "#4DCC4D", 600: "#339933", 700: "#267326", 800: "#1A4D1A",
            900: "#0D260D", 1000: "#071307",
          },
        },
      },
    },
    partnerName: "acme_bank_partner",
    id: "b1234567-aaaa-bbbb-cccc-dddddddddddd",
  },
};

function mockFetchAppConfig(sponsorId: string): Promise<AppConfig> {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (sponsorId === "error") {
        reject(new Error("Config API returned 500"));
        return;
      }
      const branding: BrandingConfig | null = MOCK_SPONSORS[sponsorId] ?? null;
      resolve({
        apiBaseUrl: "https://api.insights.fiserv.com",
        cdnUrl: "https://cdn.insights.fiserv.com",
        branding,
      });
    }, 800);
  });
}

// ============================================================
// 3. THEME UTILITIES — validate, merge, apply CSS vars
// ============================================================
function isValidThemeShape(data: unknown): data is BrandingConfig {
  if (!data || typeof data !== "object") return false;
  const d = data as Record<string, unknown>;
  const theme = d.theme as Record<string, unknown> | undefined;
  if (!theme?.colors) return false;
  const colors = theme.colors as Record<string, unknown>;
  return typeof colors.global === "object" && colors.global !== null;
}

function deepMerge<T extends Record<string, unknown>>(
  defaults: T,
  overrides: Record<string, unknown>
): T {
  const result = { ...defaults };
  for (const key of Object.keys(overrides)) {
    const ov = overrides[key];
    const dv = (defaults as Record<string, unknown>)[key];
    if (ov && typeof ov === "object" && !Array.isArray(ov) && dv && typeof dv === "object") {
      (result as Record<string, unknown>)[key] = deepMerge(
        dv as Record<string, unknown>,
        ov as Record<string, unknown>
      );
    } else if (ov !== null && ov !== undefined) {
      (result as Record<string, unknown>)[key] = ov;
    }
  }
  return result;
}

function buildTheme(apiBranding: unknown): BrandingConfig {
  if (!isValidThemeShape(apiBranding)) return DEFAULT_THEME;
  return deepMerge(
    DEFAULT_THEME as unknown as Record<string, unknown>,
    apiBranding as Record<string, unknown>
  ) as unknown as BrandingConfig;
}

function applyCssVariables(config: BrandingConfig): void {
  const root = document.documentElement;
  root.style.setProperty("--font-primary", config.theme.fonts.primary);

  const { global } = config.theme.colors;
  for (const [category, prefix] of Object.entries(COLOR_CSS_MAP)) {
    const scale = global[category as ColorCategory];
    if (!scale) continue;
    for (const [shade, value] of Object.entries(scale)) {
      root.style.setProperty(`--color-${prefix}-${shade}`, value);
    }
  }
}

// ============================================================
// 4. BRANDING CONTEXT
// ============================================================
const BrandingContext = createContext<BrandingContextValue>({
  branding: DEFAULT_THEME,
  loading: false,
  source: "defaults",
  error: null,
});

const useBranding = (): BrandingContextValue => useContext(BrandingContext);

interface BrandingProviderProps {
  sponsorId: string;
  children: ReactNode;
}

function BrandingProvider({ sponsorId, children }: BrandingProviderProps) {
  const [branding, setBranding] = useState<BrandingConfig>(DEFAULT_THEME);
  const [loading, setLoading] = useState<boolean>(false);
  const [source, setSource] = useState<string>("defaults");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    applyCssVariables(DEFAULT_THEME);
    setBranding(DEFAULT_THEME);
    setSource("defaults");
    setError(null);

    if (!sponsorId) return;

    setLoading(true);

    // -------------------------------------------------------
    // THIS IS THE API CALL
    // Replace mockFetchAppConfig with:
    //   fetch("/api/config", { signal })
    //     .then(res => res.json())
    // -------------------------------------------------------
    mockFetchAppConfig(sponsorId)
      .then((config: AppConfig) => {
        if (config.branding) {
          const theme = buildTheme(config.branding);
          setBranding(theme);
          applyCssVariables(theme);
          setSource("api");
        } else {
          setSource("defaults (sponsor not found)");
        }
      })
      .catch((err: Error) => {
        console.warn("[Branding] Config API failed, CSS defaults active", err);
        setError(err.message);
        setSource("defaults (API error)");
      })
      .finally(() => setLoading(false));
  }, [sponsorId]);

  return (
    <BrandingContext.Provider value={{ branding, loading, source, error }}>
      {children}
    </BrandingContext.Provider>
  );
}

// ============================================================
// 5. COMPONENTS — all styled via CSS variables
// ============================================================

function Header(): JSX.Element {
  const { branding } = useBranding();
  return (
    <header
      style={{
        background: "var(--color-brand-700)",
        color: "var(--color-neutral-100)",
        padding: "16px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        fontFamily: "var(--font-primary)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div
          style={{
            width: 36, height: 36, borderRadius: 8,
            background: "var(--color-brand-500)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontWeight: 700, fontSize: 16,
          }}
        >
          IN
        </div>
        <span style={{ fontSize: 18, fontWeight: 600, letterSpacing: "-0.02em" }}>
          Insights Platform
        </span>
      </div>
      <div style={{ fontSize: 13, opacity: 0.8 }}>{branding.partnerName}</div>
    </header>
  );
}

interface AlertProps {
  type: AlertType;
  title: string;
  message: string;
}

function Alert({ type, title, message }: AlertProps): JSX.Element {
  return (
    <div
      style={{
        background: `var(--color-${type}-100)`,
        borderLeft: `4px solid var(--color-${type}-600)`,
        borderRadius: "0 8px 8px 0",
        padding: "14px 18px",
        fontFamily: "var(--font-primary)",
      }}
    >
      <div style={{ fontWeight: 600, color: `var(--color-${type}-800)`, marginBottom: 4, fontSize: 14 }}>
        {title}
      </div>
      <div style={{ color: `var(--color-${type}-700)`, fontSize: 13 }}>{message}</div>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  trend?: string;
  trendCategory?: string;
}

function StatCard({ label, value, trend, trendCategory = "brand" }: StatCardProps): JSX.Element {
  return (
    <div
      style={{
        background: "var(--color-neutral-100)",
        border: "1px solid var(--color-neutral-400)",
        borderRadius: 12,
        padding: "20px 22px",
        fontFamily: "var(--font-primary)",
        flex: 1,
        minWidth: 160,
      }}
    >
      <div style={{ fontSize: 12, color: "var(--color-neutral-600)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, color: "var(--color-neutral-1000)" }}>{value}</div>
      {trend && (
        <div style={{ fontSize: 12, marginTop: 6, color: `var(--color-${trendCategory}-600)`, fontWeight: 500 }}>
          {trend}
        </div>
      )}
    </div>
  );
}

interface ButtonProps {
  children: ReactNode;
  variant?: ButtonVariant;
  onClick?: () => void;
}

function Button({ children, variant = "primary", onClick }: ButtonProps): JSX.Element {
  const variantStyles: Record<ButtonVariant, React.CSSProperties> = {
    primary: {
      background: "var(--color-brand-600)",
      color: "var(--color-neutral-100)",
      border: "none",
    },
    secondary: {
      background: "var(--color-neutral-100)",
      color: "var(--color-brand-700)",
      border: "1px solid var(--color-brand-600)",
    },
    danger: {
      background: "var(--color-critical-600)",
      color: "var(--color-neutral-100)",
      border: "none",
    },
  };

  return (
    <button
      onClick={onClick}
      style={{
        ...variantStyles[variant],
        padding: "10px 20px",
        borderRadius: 8,
        fontFamily: "var(--font-primary)",
        fontSize: 14,
        fontWeight: 600,
        cursor: "pointer",
        transition: "opacity 0.15s",
      }}
      onMouseEnter={(e) => { (e.target as HTMLButtonElement).style.opacity = "0.85"; }}
      onMouseLeave={(e) => { (e.target as HTMLButtonElement).style.opacity = "1"; }}
    >
      {children}
    </button>
  );
}

interface ColorPaletteProps {
  category: ColorCategory;
  label: string;
}

function ColorPalette({ category, label }: ColorPaletteProps): JSX.Element | null {
  const { branding } = useBranding();
  const scale: ColorScale | undefined = branding.theme.colors.global[category];
  if (!scale) return null;

  return (
    <div style={{ fontFamily: "var(--font-primary)" }}>
      <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--color-neutral-700)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
      <div style={{ display: "flex", borderRadius: 8, overflow: "hidden" }}>
        {Object.entries(scale).map(([shade, color]) => (
          <div
            key={shade}
            title={`${shade}: ${color}`}
            style={{ flex: 1, height: 32, background: color }}
          />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 3 }}>
        <span style={{ fontSize: 10, color: "var(--color-neutral-500)" }}>100</span>
        <span style={{ fontSize: 10, color: "var(--color-neutral-500)" }}>1000</span>
      </div>
    </div>
  );
}

function SourceBadge(): JSX.Element {
  const { source, loading, error } = useBranding();
  const isApi = source === "api";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-primary)" }}>
      <div
        style={{
          width: 8, height: 8, borderRadius: "50%",
          background: loading
            ? "var(--color-warning-500)"
            : isApi
              ? "var(--color-success-600)"
              : "var(--color-neutral-500)",
        }}
      />
      <span style={{ fontSize: 12, color: "var(--color-neutral-700)" }}>
        {loading ? "Loading branding..." : `Theme source: ${source}`}
      </span>
      {error && (
        <span style={{ fontSize: 12, color: "var(--color-critical-600)" }}>({error})</span>
      )}
    </div>
  );
}

// ============================================================
// 6. APP — sponsor switcher demonstrates the full flow
// ============================================================
interface SponsorOption {
  id: string;
  label: string;
}

const SPONSOR_OPTIONS: SponsorOption[] = [
  { id: "fiserv", label: "Fiserv (API branding)" },
  { id: "acmebank", label: "Acme Bank (API branding)" },
  { id: "unknown", label: "Unknown Sponsor (fallback to defaults)" },
  { id: "error", label: "API Error (fallback to defaults)" },
  { id: "", label: "No Sponsor (defaults only)" },
];

export default function App(): JSX.Element {
  const [sponsorId, setSponsorId] = useState<string>("fiserv");

  return (
    <BrandingProvider sponsorId={sponsorId}>
      <div style={{ minHeight: "100vh", background: "var(--color-neutral-200)", fontFamily: "var(--font-primary)" }}>
        <Header />

        <div style={{ maxWidth: 900, margin: "0 auto", padding: "24px 20px" }}>
          {/* Sponsor Switcher */}
          <div style={{ background: "var(--color-neutral-100)", border: "1px solid var(--color-neutral-400)", borderRadius: 12, padding: 20, marginBottom: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "var(--color-neutral-900)" }}>
                Simulate Sponsor Switch
              </div>
              <SourceBadge />
            </div>
            <div style={{ fontSize: 12, color: "var(--color-neutral-600)", marginBottom: 12 }}>
              Switch sponsors to see branding update. "Unknown" and "API Error" demonstrate fallback to defaults.
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {SPONSOR_OPTIONS.map((s: SponsorOption) => (
                <button
                  key={s.id}
                  onClick={() => setSponsorId(s.id)}
                  style={{
                    padding: "8px 14px",
                    borderRadius: 6,
                    border: sponsorId === s.id ? "2px solid var(--color-brand-600)" : "1px solid var(--color-neutral-400)",
                    background: sponsorId === s.id ? "var(--color-brand-100)" : "var(--color-neutral-100)",
                    color: sponsorId === s.id ? "var(--color-brand-700)" : "var(--color-neutral-700)",
                    fontSize: 12,
                    fontWeight: sponsorId === s.id ? 600 : 400,
                    cursor: "pointer",
                    fontFamily: "var(--font-primary)",
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          {/* Stats */}
          <div style={{ display: "flex", gap: 16, marginBottom: 20, flexWrap: "wrap" }}>
            <StatCard label="Total Revenue" value="$48,290" trend="↑ 12.5% vs last month" trendCategory="success" />
            <StatCard label="Transactions" value="1,247" trend="↑ 8.3% vs last month" trendCategory="brand" />
            <StatCard label="Avg. Ticket" value="$38.72" trend="↓ 2.1% vs last month" trendCategory="warning" />
          </div>

          {/* Alerts */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 20 }}>
            <Alert type="success" title="Payment Processed" message="Transaction #TXN-4821 completed successfully for $1,250.00" />
            <Alert type="warning" title="Settlement Pending" message="3 transactions from today are pending settlement. Expected by 11:00 PM EST." />
            <Alert type="critical" title="Verification Required" message="Account verification documents expire in 5 days. Upload updated documents." />
            <Alert type="informative" title="New Feature" message="Multi-location reporting is now available. Configure in Settings." />
          </div>

          {/* Buttons */}
          <div style={{ background: "var(--color-neutral-100)", border: "1px solid var(--color-neutral-400)", borderRadius: 12, padding: 20, marginBottom: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "var(--color-neutral-900)", marginBottom: 14 }}>
              Button Variants
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <Button variant="primary">Process Payment</Button>
              <Button variant="secondary">View Reports</Button>
              <Button variant="danger">Cancel Transaction</Button>
            </div>
          </div>

          {/* Color Palette */}
          <div style={{ background: "var(--color-neutral-100)", border: "1px solid var(--color-neutral-400)", borderRadius: 12, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "var(--color-neutral-900)", marginBottom: 16 }}>
              Active Color Palette
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px 24px" }}>
              <ColorPalette category="brand" label="Brand" />
              <ColorPalette category="brandSecondary" label="Brand Secondary" />
              <ColorPalette category="success" label="Success" />
              <ColorPalette category="critical" label="Critical" />
              <ColorPalette category="warning" label="Warning" />
              <ColorPalette category="informative" label="Informative" />
              <ColorPalette category="neutral" label="Neutral" />
            </div>
          </div>

          {/* Architecture Note */}
          <div
            style={{
              marginTop: 20, padding: 16, borderRadius: 8,
              border: "1px dashed var(--color-neutral-400)",
              fontSize: 12, color: "var(--color-neutral-600)", lineHeight: 1.6,
              fontFamily: "var(--font-primary)",
            }}
          >
            <strong style={{ color: "var(--color-neutral-800)" }}>Architecture:</strong>{" "}
            React boots with DEFAULT_THEME → BrandingProvider calls GET /api/config →
            Insights API checks Redis → miss calls External Branding App → caches response →
            returns JSON → buildTheme() validates + deep-merges over defaults →
            applyCssVariables() sets --color-* on :root → components update via CSS inheritance.
            Any failure → defaults remain. App never breaks.
          </div>
        </div>
      </div>
    </BrandingProvider>
  );
}
