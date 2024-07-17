const express = require("express");
//const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
//const firebase = require('firebase-admin');
const cors = require("cors");
//const serviceAccount = require('./serviceAccountKey.json');
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    //   "http://localhost:5174",
    //   "https://diagnocare-48d76.web.app"
  ],
  // credentials: true,
  // optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

//mfs

//Cnl3o2vnqPDseWKL
const { MongoClient, ServerApiVersion, ObjectID, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.dizfzlf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();

    const userCollection = client.db("mfsDB").collection("user");
    const transactionCollection = client.db("mfsDB").collection("transactions");


    // Secret key for JWT
const jwtSecret = process.env.ACCESS_TOKEN_SECRET; 

// Middleware for authenticating JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = user;
    next();
  });
};
/*
    // Register a new user
    app.post("/api/register", async (req, res) => {
      try {
        const { name, pin, mobileNumber, email } = req.body;

        // Check if user already exists
        const existingUser = await userCollection.findOne({
          $or: [{ mobileNumber }, { email }],
        });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }

        // Insert new user
        const newUser = {
          name,
          pin,
          mobileNumber,
          email,
          status: "pending",
          balance: 0,
        };
        const result = await userCollection.insertOne(newUser);
        res
          .status(201)
          .json({
            message: "User registered successfully",
            userId: result.insertedId,
          });
      } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).json({ message: "Failed to register user" });
      }
    });
    */

    // Registration route
app.post('/api/register', async (req, res) => {
  try{
  const { name, pin, mobileNumber, email, role } = req.body;

  // Check if user already exists
  const existingUser = await userCollection.findOne({
    $or: [{ mobileNumber }, { email }],
  });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }
 // Insert new user
  const hashedPin = await bcrypt.hash(pin, 10);
  const newUser = { 
    name,
    role, 
    pin: hashedPin, 
    mobileNumber,
    email,
    status: "pending",
    blockStatus: "active",
    balance: 0, };

  const result = await userCollection.insertOne(newUser);

  res.status(201).send({ message: 'User registered successfully', userId: result.insertedId });
}catch (error) {
  console.error("Error registering user:", error);
  res.status(500).json({ message: "Failed to register user" });
}
});

   // Login user
app.post("/api/login", async (req, res) => {
  try {

    
    const { mobileNumber, email, pin } = req.body;

    // Find user by mobileNumber or email
    const user = await userCollection.findOne({ $or: [{ email }] });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check PIN
    const isPinValid = await bcrypt.compare(pin, user.pin);
  if (!isPinValid) return res.status(401).send({ message: 'Invalid PIN' });

  // Create JWT token
  const token = jwt.sign({ email: user.email }, jwtSecret);

    // Return user details
    res.json({
      userId: user._id,
      name: user.name,
      role: user.role,
      mobileNumber: user.mobileNumber,
      email: user.email,
      balance: user.balance,
      status: user.status,
      blockStatus: user.blockStatus,
      token,
    });
    
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Login failed" });
  }
  
});

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  const { search } = req.query;
  
  try {
    let query = {};
    if (search) {
      query = { name: { $regex: search, $options: 'i' } }; // Case-insensitive search
    }
    
    const users = await userCollection.find(query).toArray();
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// Find admin----------------------------
app.get('/api/user/admin/:email', async (req, res) => {
  try {
      const token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, jwtSecret);
      const user = await userCollection.findOne({ email: decoded.email });

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      res.json({ admin: user.role === 'admin' });
  } catch (error) {
      console.error('Error fetching admin status:', error);
      res.status(500).json({ message: 'Failed to fetch admin status' });
  }
});

// Find agent----------------------------
app.get('/api/user/agent/:email', async (req, res) => {
  try {
      const token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, jwtSecret);
      const user = await userCollection.findOne({ email: decoded.email });

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      res.json({ agent: user.role === 'agent' });
  } catch (error) {
      console.error('Error fetching agent status:', error);
      res.status(500).json({ message: 'Failed to fetch agent status' });
  }
});

//find single user for overview page
app.get("/api/users/email/:email", async (req, res) => {
  const email = req.params.email;
  const user = await userCollection.findOne({ email: email });

  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }

  res.send(user);
});

//active user & send Bonus
app.patch("/api/users/status/:id", async (req, res) => {
  const id = req.params.id;
  const filter = { _id: new ObjectId(id) };
  const user = await userCollection.findOne(filter);

  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }

  let balance = 0;
  if (user.role === "agent") {
    balance = 10000;
  } else if (user.role === "user") {
    balance = 40;
  }

  const updatedDoc = {
    $set: {
      status: "active",
      balance: balance,
    },
  };

  const result = await userCollection.updateOne(filter, updatedDoc);
  res.send(result);
});
//block user
app.patch("/api/users/block/:id", async (req, res) => {
  const id = req.params.id;
  const filter = { _id: new ObjectId(id) };
  const updatedDoc = {
    $set: {
      blockStatus: "block",
    },
  };
  const result = await userCollection.updateOne(filter, updatedDoc);
  res.send(result);
});
//unblock user
app.patch("/api/users/active/:id", async (req, res) => {
  const id = req.params.id;
  const filter = { _id: new ObjectId(id) };
  const updatedDoc = {
    $set: {
      blockStatus: "active",
    },
  };
  const result = await userCollection.updateOne(filter, updatedDoc);
  res.send(result);
});

// Find block----------------------------
app.get("/api/user/block/:email", async (req, res) => {
  const email = req.params.email;
  const query = { email: email };
  const user = await userCollection.findOne(query);
  let block = false;
  if (user) {
    block = user?.blockStatus === "block";
  }
  res.send({ block });
});
// Find pending----------------------------
app.get("/api/user/status/:email", async (req, res) => {
  const email = req.params.email;
  const query = { email: email };
  const user = await userCollection.findOne(query);
  let pending = false;
  if (user) {
    pending = user?.status === "pending";
  }
  res.send({ pending });
});

//for send money
app.post('/api/send-money', authenticateToken, async (req, res) => {
  const { senderEmail, recipientEmail, amount, pin } = req.body;

  try {
    // Find sender by email
    const sender = await userCollection.findOne({ email: senderEmail });
    if (!sender) {
      return res.status(404).json({ error: "Sender not found" });
    }

    // Compare PIN using bcrypt
    const isPinValid = await bcrypt.compare(pin, sender.pin);
    if (!isPinValid) {
      return res.status(401).json({ error: "Invalid PIN" });
    }

    if (amount < 50) {
      return res.status(400).json({ error: "Transaction must be at least 50 Taka" });
    }

    // Find recipient by email
    const recipient = await userCollection.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    let transactionFee = 0;
    if (amount > 100) {
      transactionFee = 5;
    }

    const totalAmount = amount + transactionFee;
    if (sender.balance < totalAmount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Start a session for transaction
    const session = client.startSession();
    session.startTransaction();

    try {
      await userCollection.updateOne(
        { email: senderEmail },
        { $inc: { balance: -totalAmount } },
        { session }
      );

      await userCollection.updateOne(
        { email: recipientEmail },
        { $inc: { balance: amount } },
        { session }
      );

      // Log transaction
      await transactionCollection.insertOne(
        {
          senderEmail,
          recipientEmail,
          amount,
          transactionFee,
          totalAmount,
          date: new Date()
        },
        { session }
      );

      await session.commitTransaction();
      session.endSession();

      res.json({ message: "Transaction successful" });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      console.error("Transaction error:", error);
      res.status(500).json({ error: "Transaction failed" });
    }
  } catch (error) {
    console.error("Internal server error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

 // Cash-out route
 app.post('/api/cash-out', authenticateToken, async (req, res) => {
  const { agentEmail, amount, pin } = req.body;
  const user = req.user;

  try {
    // Find user by email
    const currentUser = await userCollection.findOne({ email: user.email });
    if (!currentUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify PIN
    const isPinValid = await bcrypt.compare(pin, currentUser.pin);
    if (!isPinValid) {
      return res.status(401).json({ error: "Invalid PIN" });
    }

    // Find agent by email
    const agent = await userCollection.findOne({ email: agentEmail });
    if (!agent || agent.role !== 'agent') {
      return res.status(404).json({ error: "Agent not found" });
    }

    // Calculate transaction fee
    const transactionFee = amount * 0.015; // 1.5% fee

    // Total amount to deduct from user (amount + fee)
    const totalAmountToDeduct = amount + transactionFee;

    // Check user balance
    if (currentUser.balance < totalAmountToDeduct) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Start a session for transaction
    const session = client.startSession();
    session.startTransaction();

    try {
      // Deduct amount from user's balance
      await userCollection.updateOne(
        { email: currentUser.email },
        { $inc: { balance: -totalAmountToDeduct } },
        { session }
      );

      // Add amount to agent's balance
      await userCollection.updateOne(
        { email: agent.email },
        { $inc: { balance: amount } },
        { session }
      );

      // Log transaction
      await transactionCollection.insertOne(
        {
          senderEmail: currentUser.email,
          recipientEmail: agent.email,
          amount,
          transactionFee,
          totalAmount: totalAmountToDeduct,
          date: new Date()
        },
        { session }
      );

      await session.commitTransaction();
      session.endSession();

      res.json({ message: "Cash-out successful" });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      res.status(500).json({ error: "Transaction failed" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});


// Paginated transaction history for a single user
app.get('/api/transactions', async (req, res) => {
  const { email, page = 1, limit = 3 } = req.query;

  try {
    const skip = (page - 1) * limit;
    const totalTransactions = await transactionCollection.countDocuments({
      $or: [{ senderEmail: email }, { recipientEmail: email }]
    });

    const transactions = await transactionCollection
      .find({ $or: [{ senderEmail: email }, { recipientEmail: email }] })
      .sort({ date: -1 }) // Sort by date descending
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    const totalPages = Math.ceil(totalTransactions / limit);

    res.json({ transactions, totalPages });
  } catch (error) {
    console.error('Error fetching transaction history', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// all transaction for system monitoring page
app.get('/api/all-transactions', authenticateToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 3;
  const skip = (page - 1) * limit;

  try {
    const transactions = await transactionCollection.find({}).skip(skip).limit(limit).toArray();
    const totalTransactions = await transactionCollection.countDocuments({});
    const totalPages = Math.ceil(totalTransactions / limit);

    res.json({ transactions, totalPages, currentPage: page });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});





/*
// Get user balance
app.get('/api/balance', authenticateToken, async (req, res) => {
  const user = await userCollection.findOne({ email: req.user.email });
  if (!user) return res.status(404).send({ message: 'User not found' });

  res.send({ balance: user.balance });

});
*/

    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("MFS server is running....");
});

app.listen(port, () => {
  console.log(`MFS server is running on port: ${port}`);
});
