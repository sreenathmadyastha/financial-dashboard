/**
 * Melio side (runs in the PARENT page that hosts the Insights iframe).
 *
 * Subscribes to height-change events published by the Insights app and
 * adjusts the iframe's height to match, replacing the fixed height.
 *
 * Hand this to the Melio team as the reference implementation / contract.
 */

const INSIGHTS_ORIGIN = 'https://insights.yourdomain.com'; // exact origin of the Insights app
const MIN_HEIGHT = 200;
const MAX_HEIGHT = 20000; // sanity ceiling against bogus values

interface HeightChangeMessage {
  source: 'cfc-insights';
  type: 'INSIGHTS_HEIGHT_CHANGE';
  height: number;
}

function isHeightChangeMessage(data: unknown): data is HeightChangeMessage {
  const d = data as HeightChangeMessage;
  return (
    d != null &&
    d.source === 'cfc-insights' &&
    d.type === 'INSIGHTS_HEIGHT_CHANGE' &&
    typeof d.height === 'number' &&
    Number.isFinite(d.height)
  );
}

export function subscribeToInsightsHeight(iframe: HTMLIFrameElement): () => void {
  const onMessage = (event: MessageEvent): void => {
    // 1. Trust only the Insights origin.
    if (event.origin !== INSIGHTS_ORIGIN) return;

    // 2. Trust only messages from THIS iframe (page has two iframes).
    if (event.source !== iframe.contentWindow) return;

    // 3. Validate the payload shape.
    if (!isHeightChangeMessage(event.data)) return;

    const height = Math.min(Math.max(event.data.height, MIN_HEIGHT), MAX_HEIGHT);
    iframe.style.height = `${height}px`;
  };

  window.addEventListener('message', onMessage);

  // Ask Insights to (re-)publish its current height in case its initial
  // event fired before this listener was attached.
  iframe.addEventListener(
    'load',
    () => {
      iframe.contentWindow?.postMessage(
        { type: 'REQUEST_INSIGHTS_HEIGHT' },
        INSIGHTS_ORIGIN
      );
    },
    { once: true }
  );

  return () => window.removeEventListener('message', onMessage);
}

/* Example wiring:
 *
 *   const insightsIframe = document.getElementById('insights-iframe') as HTMLIFrameElement;
 *   const unsubscribe = subscribeToInsightsHeight(insightsIframe);
 *
 * Recommended iframe markup:
 *   <iframe id="insights-iframe"
 *           src="https://insights.yourdomain.com/..."
 *           scrolling="no"
 *           style="width: 100%; height: 600px; border: 0; overflow: hidden;">
 *   </iframe>
 */
