import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import connectDB from './database/db.js';

//Importing Routes
import testroute from "./routes/user.routes.js";


//Initiasing App
const app = express();

app.use(helmet());
dotenv.config();


// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple request logger to help debug incoming API calls
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.get("/", (req, res) => {
  res.status(200).json({
    message: "Welcome to Backend Server",
  });
});


app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  })
);

//Using Routes:
app.use("/api/v1/user", testroute);

const PORT = process.env.PORT;

// Start server only after successful DB connection
(async () => {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`✅ Backend Server is running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Server startup aborted due to DB connection failure');
    process.exit(1);
  }
})();
