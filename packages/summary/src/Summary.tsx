import React from "react";
import { useAccessToken } from "@finance/shared-auth";

export interface SummaryProps {
    accessToken: string;
    refreshUrl: string;
    data: { totalIn: number; totalOut: number };
}

const Summary: React.FC<SummaryProps> = ({ accessToken, refreshUrl, data }) => {
    //  const token = useAccessToken({ initialToken: accessToken, refreshUrl });
    const token = "test"

    if (!token) return <div>Refreshing token...</div>;



    // alert(jsonData)

    return (
        <div style={{ border: "1px solid blue", padding: "1rem", borderRadius: 8 }}>
            <h3>Financial Summary</h3>
            {data ? (
                <div>
                    <p>Total In: ${data.totalIn || 0}</p>
                    <p>Total Out: ${data.totalOut || 0}</p>
                </div>
            ) : (
                <p>No summary data. Token: {accessToken ? 'Valid' : 'Missing'}</p>
            )}

        </div>
    );
};

export default Summary;
