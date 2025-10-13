import React from "react";
import { useAccessToken } from "@finance/shared-auth";

export interface MoneyOutProps {
    accessToken: string;
    refreshUrl: string;
    jsonData: { amount: number; category: string; date: string }[];
}

const MoneyOut: React.FC<MoneyOutProps> = ({ accessToken, refreshUrl, data }) => {
    // const token = useAccessToken({ initialToken: accessToken, refreshUrl });
    const token = "test";

    if (!token) return <div>Refreshing token...</div>;

    return (
        <div style={{ border: "1px solid red", padding: "1rem", borderRadius: 8 }}>
            <h3>💸 Money Out</h3>
            <ul>
                {data ? (
                    <div>
                        <p>Amount: ${data.jsonData.amount || 0}</p>
                        <p>Source: {data.jsonData.source}</p>
                        <p>Date: {data.jsonData.date}</p>
                    </div>
                ) : (
                    <p>No moneyIn data. Token: {accessToken ? 'Valid' : 'Missing'}</p>
                )}
            </ul>
            <small>Token: {token.slice(0, 10)}...</small>
        </div>
    );
};

export default MoneyOut;
