// src/hooks/useSessionGuard.ts
import { useEffect } from 'react';

export const useSessionGuard = () => {
    useEffect(() => {
        // Clear token only when navigating away (not minimize)
        const handlePageHide = (event: PageTransitionEvent) => {
            if (event.persisted) {
                // Page is being stored in bfcache (user navigating away)
                sessionStorage.removeItem('accessToken');
            }
        };

        // Handle back button - page restored from cache
        const handlePageShow = (event: PageTransitionEvent) => {
            if (event.persisted) {
                const token = sessionStorage.getItem('accessToken');
                if (!token) {
                    window.location.replace('/login');
                }
            }
        };

        window.addEventListener('pagehide', handlePageHide);
        window.addEventListener('pageshow', handlePageShow);

        return () => {
            window.removeEventListener('pagehide', handlePageHide);
            window.removeEventListener('pageshow', handlePageShow);
        };
    }, []);
};