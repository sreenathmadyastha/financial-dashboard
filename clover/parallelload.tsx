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