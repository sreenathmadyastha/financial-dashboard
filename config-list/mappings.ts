function reconstructMonthlyData(apiResponse: any) {
    const { overallSummary, periodInfo } = apiResponse;
    const { allMonths } = periodInfo;

    // Step 1: Create a map of existing data by index
    const dataMap = new Map(
        overallSummary.map(item => [item.index, item])
    );
    // dataMap now has: { 1 => {May-25 data}, 4 => {Aug-25 data} }

    // Step 2: Loop through ALL months and fill gaps
    return allMonths.map((month: any, idx: any) => {
        const index = idx + 1; // 1, 2, 3, 4, 5, 6

        // If data exists for this index, use it
        if (dataMap.has(index)) {
            return dataMap.get(index);
        }

        // Otherwise, create empty entry for the gap
        return {
            index,
            monthYear: month,
            total: 0,
            categories: {
                "moneyInTotal": 0,
                "moneyOutTotal": 0
            },
            isEmpty: true // Helpful flag for UI
        };
    });
}