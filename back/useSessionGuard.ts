// src/hooks/useSessionGuard.ts
import { useEffect, useLayoutEffect } from 'react';

export const useSessionGuard = () => {
    // Check token immediately before paint
    useLayoutEffect(() => {
        const token = sessionStorage.getItem('accessToken');
        if (!token) {
            window.location.replace('/login');
        }
    }, []);

    useEffect(() => {
        const handleVisibilityChange = () => {
            if (document.visibilityState === 'hidden') {
                sessionStorage.removeItem('accessToken');
            }
        };

        const handlePageShow = (event: PageTransitionEvent) => {
            if (event.persisted) {
                const token = sessionStorage.getItem('accessToken');
                if (!token) {
                    window.location.replace('/login');
                }
            }
        };

        // Disable bfcache
        window.addEventListener('unload', () => { });

        document.addEventListener('visibilitychange', handleVisibilityChange);
        window.addEventListener('pageshow', handlePageShow);

        return () => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
            window.removeEventListener('pageshow', handlePageShow);
        };
    }, []);
};