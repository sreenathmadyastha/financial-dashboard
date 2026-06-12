import React, { Component, ErrorInfo, ReactNode } from 'react';

// Dynatrace RUM global (loaded by the OneAgent JS snippet)
declare global {
  interface Window {
    dtrum?: {
      reportError: (error: Error | string, parentActionId?: number) => void;
    };
  }
}

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional custom fallback UI. Receives the error and a reset callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Identifies which part of the app failed, e.g. "InsightsDashboard" */
  boundaryName?: string;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  // Called during render phase — update state so next render shows fallback
  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  // Called during commit phase — safe place for side effects (logging)
  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    const name = this.props.boundaryName ?? 'ErrorBoundary';

    // Send to Dynatrace RUM so you get stack traces from CERT/PROD sessions
    window.dtrum?.reportError(
      new Error(`[${name}] ${error.message}\nComponentStack: ${errorInfo.componentStack}`)
    );

    // Always log locally too (visible in DevTools console)
    console.error(`[${name}] Uncaught render error:`, error, errorInfo.componentStack);
  }

  private reset = (): void => {
    this.setState({ error: null });
  };

  render(): ReactNode {
    const { error } = this.state;
    const { children, fallback } = this.props;

    if (error) {
      if (fallback) {
        return fallback(error, this.reset);
      }
      // Default fallback
      return (
        <div role="alert" style={{ padding: '2rem', textAlign: 'center' }}>
          <h2>Something went wrong loading this section.</h2>
          <p style={{ color: '#666' }}>{error.message}</p>
          <button onClick={this.reset}>Try again</button>
        </div>
      );
    }

    return children;
  }
}

export default ErrorBoundary;
