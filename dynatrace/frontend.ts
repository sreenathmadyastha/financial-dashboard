// lib/tracking/insightsTracker.ts
export function trackAction(
    feature: string,        // e.g. 'MoneyIn', 'Transactions'
    event: string,          // e.g. 'ChartDrilldown', 'FilterApplied'
    properties?: Record<string, string | number>
) {
    if (typeof window.dtrum === 'undefined') return;

    const actionName = `Insights:${feature}:${event}`;
    const actionId = window.dtrum.enterAction(actionName);

    if (properties) {
        Object.entries(properties).forEach(([k, v]) => {
            window.dtrum.addActionProperty(actionId, k, typeof v === 'number' ? 'double' : 'string', v);
        });
    }

    window.dtrum.leaveAction(actionId);
}

//Call it like: trackAction('MoneyIn', 'ChartDrilldown', { period: '30d', widget: 'bar' }).
// This produces clean funnel-able paths in Dynatrace's Session
// Segmentation and User Sessions views, and you can build DQL queries by useraction.name prefix.
//
//Set this once at session initialization (after your OIDC token exchange resolves in SponsorContextPreProcessor):

// In your session bootstrap — after SponsorContext loads
function initSession(sponsorId: string, correlationId: string) {
    if (typeof window.dtrum === 'undefined') return;

    // true = captured with each beacon, visible in DQL
    window.dtrum.addSessionProperty('track_id', correlationId, true);
    window.dtrum.addSessionProperty('sponsor_id', sponsorId, true);
    window.dtrum.sendSessionProperties();
}

// In Dynatrace Notebooks or dashboards you then query:
// fetch dt.entity.user_session | filter track_id == "xyz".
// The track_id flows into every action on that session automatically.

// UC3 — First - time vs.returning visitors(encrypted identity)
// The core principle: Dynatrace never sees raw subscriber or business user IDs.
// // You hash them server-side and inject only the hash. The mapping lives entirely in your infrastructure.