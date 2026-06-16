/**
 * Insights side (runs INSIDE the iframe).
 *
 * Observes the document's content height and publishes it to the parent
 * (Melio) window whenever it changes. Melio listens for these events and
 * resizes the iframe accordingly.
 *
 * Usage (e.g. in App.tsx):
 *   useIframeHeightPublisher();
 */
import { useEffect } from 'react';

// Lock this down per environment via Vite env vars.
// e.g. VITE_PARENT_ORIGIN=https://app.melio.com
const PARENT_ORIGIN: string = import.meta.env.VITE_PARENT_ORIGIN ?? '';

export interface HeightChangeMessage {
  source: 'cfc-insights';
  type: 'INSIGHTS_HEIGHT_CHANGE';
  height: number;
}

export function useIframeHeightPublisher(targetOrigin: string = PARENT_ORIGIN): void {
  useEffect(() => {
    // Not embedded (running standalone) -> nothing to do.
    if (window.self === window.top) return;

    if (!targetOrigin) {
      console.warn('[insights] PARENT_ORIGIN not configured; height events disabled.');
      return;
    }

    let lastHeight = 0;
    let rafId = 0;

    const measureAndPublish = (): void => {
      // scrollHeight of <html> reflects full rendered content height
      const height = Math.ceil(document.documentElement.scrollHeight);

      if (height > 0 && height !== lastHeight) {
        lastHeight = height;
        const message: HeightChangeMessage = {
          source: 'cfc-insights',
          type: 'INSIGHTS_HEIGHT_CHANGE',
          height,
        };
        window.parent.postMessage(message, targetOrigin);
      }
    };

    // Coalesce bursts of layout changes into one post per animation frame.
    const schedule = (): void => {
      cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(measureAndPublish);
    };

    // 1. ResizeObserver: catches layout/size changes (charts rendering,
    //    accordions expanding, data loading, window resize reflow, etc.)
    const resizeObserver = new ResizeObserver(schedule);
    resizeObserver.observe(document.documentElement);
    resizeObserver.observe(document.body);

    // 2. MutationObserver fallback: catches DOM insert/remove that may not
    //    immediately change the observed boxes (e.g. async route content).
    const mutationObserver = new MutationObserver(schedule);
    mutationObserver.observe(document.body, { childList: true, subtree: true });

    // 3. Late-loading assets (images/fonts) can change height after load.
    window.addEventListener('load', schedule);

    // 4. Parent can request a re-publish (e.g. after it mounts its listener).
    const onMessage = (event: MessageEvent): void => {
      if (event.origin !== targetOrigin) return;
      if (event.data?.type === 'REQUEST_INSIGHTS_HEIGHT') {
        lastHeight = 0; // force re-send even if unchanged
        schedule();
      }
    };
    window.addEventListener('message', onMessage);

    // Initial publish on mount.
    measureAndPublish();

    return () => {
      cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      mutationObserver.disconnect();
      window.removeEventListener('load', schedule);
      window.removeEventListener('message', onMessage);
    };
  }, [targetOrigin]);
}
