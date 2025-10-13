import React from "react";
import MoneyIn from "@finance/money-in";
import { MoneyOut } from "@finance/money-out";
import Summary from "@finance/summary";

const Dashboard: React.FC = () => {
    const initialAccessToken = "initial-token";
    // const refreshUrl = "http://localhost:4000/api/refresh-token"; // mock API
    const refreshUrl = ""
    const moneyInData = { amount: 1200, source: "Salary", date: "2025-10-01" }

    const moneyOutData =
        { amount: 1200, source: "Salary", date: "2025-10-01" }


    const summaryData = {
        totalIn: 1500,
        totalOut: 700,
    };

    return (
        <div style={{ display: "grid", gap: "1rem", padding: "2rem" }}>
            <Summary accessToken={initialAccessToken} refreshUrl={refreshUrl} data={summaryData} />
            <MoneyIn accessToken={initialAccessToken} refreshUrl={refreshUrl} jsonData={moneyInData} />

        </div>
    );
};

export default Dashboard;
