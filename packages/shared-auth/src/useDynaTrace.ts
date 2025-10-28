import { useCallback, useEffect, useRef } from 'react';

// Extend the Window interface to include dtrum
declare global {
    interface Window {
        dtrum?: {
            reportError: (error: Error | string, parentActionId?: number) => void;
            enterAction: (actionName: string, actionType?: string, startTime?: number) => number;
            leaveAction: (actionId: number, stopTime?: number) => void;
            addActionProperties: (actionId: number, properties: Record<string, string | number | boolean>) => void;
            sendSessionProperties: (properties: Record<string, string | number | boolean>) => void;
            identifyUser: (userId: string) => void;
            endSession: () => void;
            now: () => number;
        };
    }
}
// Basic implementation of Dynatrace logging

interface DynatraceLogger {
    reportError: (error: Error | string, context?: Record<string, any>) => void;
    logAction: (actionName: string, actionType?: string) => number | null;
    endAction: (actionId: number | null) => void;
    addProperties: (actionId: number | null, properties: Record<string, string | number | boolean>) => void;
    setSessionProperties: (properties: Record<string, string | number | boolean>) => void;
    identifyUser: (userId: string) => void;
    trackAsync: <T>(actionName: string, asyncFn: () => Promise<T>, actionType?: string) => Promise<T>;
    isDynatraceAvailable: boolean;
}

interface UseDynatraceOptions {
    enableLogging?: boolean;
    fallbackLogger?: (message: string, data?: any) => void;
}

/**
 * Custom React hook for Dynatrace logging
 * 
 * @param options - Configuration options for the hook
 * @returns DynatraceLogger object with logging methods
 * 
 * @example
 * const { reportError, logAction, endAction, trackAsync } = useDynatrace();
 * 
 * // Report an error
 * reportError(new Error('Something went wrong'), { userId: '123' });
 * 
 * // Track a user action
 * const actionId = logAction('Button Click', 'user-action');
 * // ... perform action
 * endAction(actionId);
 * 
 * // Track async operations
 * await trackAsync('API Call', async () => {
 *   return await fetchData();
 * });
 */

export const useDynatrace = (options: UseDynatraceOptions = {}): DynatraceLogger => {
    const { enableLogging = true, fallbackLogger = console.log } = options;
    const isDynatraceAvailable = useRef(typeof window !== 'undefined' && !!window.dtrum);

    useEffect(() => {
        // Check if Dynatrace is available on mount
        isDynatraceAvailable.current = typeof window !== 'undefined' && !!window.dtrum;

        if (!isDynatraceAvailable.current && enableLogging) {
            fallbackLogger('Dynatrace RUM agent not detected. Make sure the dtrum script is loaded.');
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Report an error to Dynatrace
     */
    const reportError = useCallback((error: Error | string, context?: Record<string, any>) => {
        if (!enableLogging) return;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                const errorObj = typeof error === 'string' ? new Error(error) : error;

                // Add context as properties if provided
                if (context) {
                    // Create a custom error with context
                    const enrichedError = new Error(errorObj.message);
                    enrichedError.name = errorObj.name;
                    enrichedError.stack = errorObj.stack;
                    (enrichedError as any).context = context;
                }

                window.dtrum.reportError(errorObj);

                if (context && enableLogging) {
                    fallbackLogger('Dynatrace error reported with context:', context);
                }
            } catch (e) {
                fallbackLogger('Failed to report error to Dynatrace:', e);
            }
        } else {
            fallbackLogger('Dynatrace not available. Error:', error, context);
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Start tracking a user action
     */
    const logAction = useCallback((actionName: string, actionType: string = 'custom'): number | null => {
        if (!enableLogging) return null;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                return window.dtrum.enterAction(actionName, actionType);
            } catch (e) {
                fallbackLogger('Failed to log action to Dynatrace:', e);
                return null;
            }
        } else {
            fallbackLogger(`Dynatrace not available. Action: ${actionName} (${actionType})`);
            return null;
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * End tracking a user action
     */
    const endAction = useCallback((actionId: number | null) => {
        if (!enableLogging || actionId === null) return;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                window.dtrum.leaveAction(actionId);
            } catch (e) {
                fallbackLogger('Failed to end action in Dynatrace:', e);
            }
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Add properties to an action
     */
    const addProperties = useCallback((
        actionId: number | null,
        properties: Record<string, string | number | boolean>
    ) => {
        if (!enableLogging || actionId === null) return;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                window.dtrum.addActionProperties(actionId, properties);
            } catch (e) {
                fallbackLogger('Failed to add properties to Dynatrace action:', e);
            }
        } else {
            fallbackLogger('Dynatrace not available. Properties:', properties);
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Set session-level properties
     */
    const setSessionProperties = useCallback((properties: Record<string, string | number | boolean>) => {
        if (!enableLogging) return;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                window.dtrum.sendSessionProperties(properties);
            } catch (e) {
                fallbackLogger('Failed to set session properties in Dynatrace:', e);
            }
        } else {
            fallbackLogger('Dynatrace not available. Session properties:', properties);
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Identify the current user
     */
    const identifyUser = useCallback((userId: string) => {
        if (!enableLogging) return;

        if (isDynatraceAvailable.current && window.dtrum) {
            try {
                window.dtrum.identifyUser(userId);
            } catch (e) {
                fallbackLogger('Failed to identify user in Dynatrace:', e);
            }
        } else {
            fallbackLogger(`Dynatrace not available. User ID: ${userId}`);
        }
    }, [enableLogging, fallbackLogger]);

    /**
     * Track an async operation with automatic action start/end
     */
    const trackAsync = useCallback(async <T,>(
        actionName: string,
        asyncFn: () => Promise<T>,
        actionType: string = 'async-operation'
    ): Promise<T> => {
        const actionId = logAction(actionName, actionType);

        try {
            const result = await asyncFn();
            endAction(actionId);
            return result;
        } catch (error) {
            reportError(error as Error, { action: actionName });
            endAction(actionId);
            throw error;
        }
    }, [logAction, endAction, reportError]);

    return {
        reportError,
        logAction,
        endAction,
        addProperties,
        setSessionProperties,
        identifyUser,
        trackAsync,
        isDynatraceAvailable: isDynatraceAvailable.current,
    };
};

export default useDynatrace;