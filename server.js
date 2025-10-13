import express from "express";
const app = express();
app.use(express.json());

app.post("/api/refresh-token", (req, res) => {
  const newToken = "token-" + Math.random().toString(36).substring(2, 12);
  console.log("Refreshing token →", newToken);
  res.json({ accessToken: newToken });
});

app.listen(4000, () => console.log("Mock API running on http://localhost:4000"));