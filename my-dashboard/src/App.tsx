
import MoneyIn from "@finance/money-in";

function App() {
  const initialAccessToken = "initial-token";
  const refreshUrl = ""
  const moneyInData =
    { amount: 1200, source: "Salary", date: "2025-10-01" }

  return (
    <div>
      <h1>Financial Dashboard</h1>
      <MoneyIn accessToken={initialAccessToken} refreshUrl={refreshUrl} jsonData={moneyInData} />
    </div>
  );
}

export default App;
