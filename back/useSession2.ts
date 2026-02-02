// src/hooks/useSessionGuard.ts
import { useEffect } from 'react';

export const useSessionGuard = () => {
    useEffect(() => {
        // Clear token when user leaves the page
        const handleVisibilityChange = () => {
            if (document.visibilityState === 'hidden') {
                sessionStorage.removeItem('accessToken');
            }
        };

        // Handle back button - page restored from cache
        const handlePageShow = (event: PageTransitionEvent) => {
            if (event.persisted) {
                // Token was cleared when they left, so redirect to login
                window.location.replace('/login');
            }
        };

        document.addEventListener('visibilitychange', handleVisibilityChange);
        window.addEventListener('pageshow', handlePageShow);

        return () => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
            window.removeEventListener('pageshow', handlePageShow);
        };
    }, []);
};