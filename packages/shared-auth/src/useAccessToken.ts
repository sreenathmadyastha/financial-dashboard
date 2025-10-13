import { useState, useEffect } from "react";

export interface UseAccessTokenResult {
  token: string;
  isRefreshing: boolean;
}

export function useAccessToken(initialToken: string): UseAccessTokenResult {
  const [token, setToken] = useState(initialToken);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    const refresh = async () => {
      try {
        setIsRefreshing(true);
        // const res = await fetch("http://localhost:4000/api/refresh-token", {
        //   method: "POST",
        //   headers: { "Content-Type": "application/json" },
        //   body: JSON.stringify({ currentToken: token }),
        // });
        // const data = await res.json();
        const data = "test";
        setToken(data);
      } catch (err) {
        console.error("Token refresh failed", err);
      } finally {
        setIsRefreshing(false);
      }
    };

    const interval = setInterval(refresh, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [token]);

  return { token, isRefreshing };
}
