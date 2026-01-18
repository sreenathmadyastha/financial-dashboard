// 4. React Query / TanStack Query (Recommended for production)
// Handles caching, loading states, and parallel fetching elegantly.

function Dashboard() {
    const insight = useQuery({ queryKey: ['insight'], queryFn: fetchInsightSummary });
    const clover = useQuery({ queryKey: ['clover'], queryFn: fetchCloverIntegration });

    const isLoading = insight.isLoading || clover.isLoading;

    if (isLoading) return <Skeleton />;

    return (
        <div>
            <InsightPanel data={insight.data} />
            <CloverPanel data={clover.data} />
        </div>
    );
}

// Show All at Once, But Start Both Early
// Fire both requests immediately but only render when both 
// complete—best of both worlds if you need synchronized display.

function Dashboard() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        Promise.all([fetchInsightSummary(), fetchCloverIntegration()])
            .then(([insight, clover]) => setData({ insight, clover }))
            .finally(() => setLoading(false));
    }, []);

    if (loading) return <FullPageSkeleton />;
    return <Dashboard insight={data.insight} clover={data.clover} />;
}

// Show data as it arrives, with loading states for pending data.
// typescript
function Dashboard() {
    const [insight, setInsight] = useState(null);
    const [clover, setClover] = useState(null);

    useEffect(() => {
        fetchInsightSummary().then(setInsight);
        fetchCloverIntegration().then(setClover);
    }, []);

    return (
        <div>
            {insight ? <InsightPanel data={insight} /> : <Skeleton />}
            {clover ? <CloverPanel data={clover} /> : <Skeleton />}
        </div>
    );
}