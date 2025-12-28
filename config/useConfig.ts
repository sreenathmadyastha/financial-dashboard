// src/hooks/useConfig.ts (custom hook for fetching)
import { useState, useEffect } from 'react';
import { AppConfig } from '../types/Config';

export const useConfig = (): { config: AppConfig | null; loading: boolean; error: string | null } => {
    const [config, setConfig] = useState<AppConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const response = await fetch('/api/config');  // Relative URL—no base needed!
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data: AppConfig = await response.json();
                setConfig(data);
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Failed to load config');
            } finally {
                setLoading(false);
            }
        };

        fetchConfig();
    }, []);

    return { config, loading, error };
};