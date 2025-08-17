// Load environment variables
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripeLib = require("stripe");
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const SSLCommerzPayment = require('sslcommerz-nodesdk');

const app = express();
const port = process.env.PORT || 3000;
const stripe = stripeLib(process.env.STRIPE_SECRET_KEY);



// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded());

// MongoDB Setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@tanimweb.1iucvax.mongodb.net/?retryWrites=true&w=majority&appName=TanimWeb`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Helper: Validate and create ObjectId
const createObjectId = (id) => {
  if (!id) return null;
  if (!ObjectId.isValid(id)) return null;
  return new ObjectId(id);
};


// JWT verification middleware
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).send({ error: true, message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  if (!token)
    return res.status(401).send({ error: true, message: "Token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).send({ error: true, message: "Forbidden" });

    req.user = decoded;
    next();
  });
};

// Store name: testbogurjev8
// Registered URL: www.bogurabashi.com
// Session API to generate transaction: https://sandbox.sslcommerz.com/gwprocess/v3/api.php
// Validation API: https://sandbox.sslcommerz.com/validator/api/validationserverAPI.php?wsdl
// Validation API (Web Service) name: https://sandbox.sslcommerz.com/validator/api/validationserverAPI.php


// Main async function to run server logic
async function run() {
  try {
    // await client.connect();
    // console.log("✅ MongoDB connected");

    const db = client.db("apporbitDB");
    const users = db.collection("users");
    const products = db.collection("products");
    const reviews = db.collection("reviews");
    const coupons = db.collection("coupons");
    const payments = db.collection("payments");

 // Payment Initiate Route
    app.post('/api/payment/initiate', async (req, res) => {
      const { amount, name, email, phone, productName } = req.body;
      const transactionId = new ObjectId().toString(); // Unique Transaction ID

      const data = {
        total_amount: amount,
        currency: 'BDT',
        tran_id: transactionId,
        success_url: `http://localhost:5000/api/payment/success/${transactionId}`,
        fail_url: `http://localhost:5000/api/payment/fail/${transactionId}`,
        cancel_url: `http://localhost:5000/api/payment/cancel/${transactionId}`,
        ipn_url: `http://localhost:5000/api/payment/ipn`,
        shipping_method: 'Courier',
        product_name: productName,
        product_category: 'General',
        product_profile: 'general',
        cus_name: name,
        cus_email: email,
        cus_add1: 'Dhaka',
        cus_add2: 'Dhaka',
        cus_city: 'Dhaka',
        cus_state: 'Dhaka',
        cus_postcode: '1207',
        cus_country: 'Bangladesh',
        cus_phone: phone,
        cus_fax: 'N/A',
        ship_name: name,
        ship_add1: 'Dhaka',
        ship_add2: 'Dhaka',
        ship_city: 'Dhaka',
        ship_state: 'Dhaka',
        ship_postcode: 1207,
        ship_country: 'Bangladesh',
      };

      // Save pending payment info
      await payments.insertOne({
        transactionId,
        name,
        email,
        phone,
        amount,
        productName,
        status: 'Pending',
        date: new Date(),
      });

      const sslcz = new SSLCommerzPayment(process.env.STORE_ID, process.env.STORE_PASSWORD, false); // false for sandbox
      sslcz.init(data).then(apiResponse => {
        if (apiResponse?.GatewayPageURL) {
          res.send({ GatewayPageURL: apiResponse.GatewayPageURL });
        } else {
          res.status(400).send({ message: 'Payment initiation failed' });
        }
      }).catch(err => {
        res.status(500).send({ message: 'SSLCommerz error', error: err });
      });
    });

    // JWT token generation
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      if (!email)
        return res.status(400).send({ error: true, message: "Email is required" });
    
      // Fetch user from DB
      const user = await users.findOne({ email });
      if (!user)
        return res.status(404).send({ error: true, message: "User not found" });
    
      // Sign token including role
      const token = jwt.sign(
        { email, role: user.role || "user" },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );
    
      res.send({ token });
    });
    

    // User routes
    app.post("/users", async (req, res) => {
      const exists = await users.findOne({ email: req.body.email });
      if (exists) return res.send({ message: "User already exists" });
      const result = await users.insertOne(req.body);
      res.send(result);
    });

    app.get("/users", async (_, res) => {
      const allUsers = await users.find().toArray();
      res.send(allUsers);
    });

    app.patch("/users/role/:id", async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const result = await users.updateOne(
        { _id: objectId },
        { $set: { role: req.body.role } }
      );
      res.send(result);
    });

    app.patch("/users/subscribe/:email", async (req, res) => {
      const result = await users.updateOne(
        { email: req.params.email },
        { $set: { membership: "verified" } }
      );
      res.send(result);
    });

    app.get("/users/role/:email", async (req, res) => {
      const user = await users.findOne({ email: req.params.email });
      res.send({ role: user?.role || null });
    });

    app.get("/users/profile/:email", verifyJWT, async (req, res) => {
      if (req.params.email !== req.user.email)
        return res.status(403).send({ error: true, message: "Forbidden" });

      const user = await users.findOne({ email: req.params.email });
      if (!user) return res.status(404).send({ error: "User not found" });

      res.send({
        name: user.name,
        email: user.email,
        role: user.role,
        membership: user.membership || null,
        photoURL: user.photoURL || null,
      });
    });
    app.patch("/users/profile/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
    
      // Check if the requester is the owner of the profile
      if (email !== req.user.email) {
        return res.status(403).send({ error: true, message: "Forbidden" });
      }
    
      const updateData = req.body;
    
      try {
        const result = await users.updateOne(
          { email: email },
          { $set: updateData }
        );
    
        if (result.matchedCount === 0) {
          return res.status(404).send({ error: true, message: "User not found" });
        }
    
        res.send({
          success: true,
          message: "User profile updated successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error("Failed to update user profile:", error);
        res.status(500).send({ error: true, message: "Internal server error" });
      }
    });

    // Get user statistics
    app.get("/users/stats/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        
        // Check if the requester is the owner of the profile or admin
        if (email !== req.user.email && req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden" });
        }

        // Get user's products count by status
        const totalProducts = await products.countDocuments({ ownerEmail: email });
        const acceptedProducts = await products.countDocuments({ 
          ownerEmail: email, 
          status: "accepted" 
        });
        const pendingProducts = await products.countDocuments({ 
          ownerEmail: email, 
          status: "pending" 
        });
        const rejectedProducts = await products.countDocuments({ 
          ownerEmail: email, 
          status: "rejected" 
        });

        // Get user's reviews count
        const totalReviews = await reviews.countDocuments({ userEmail: email });

        // Get user's total upvotes received
        const userProducts = await products.find({ ownerEmail: email }).toArray();
        const totalUpvotes = userProducts.reduce((sum, product) => sum + (product.upvotes || 0), 0);

        // Get user's membership status
        const user = await users.findOne({ email });
        const membership = user?.membership || "basic";

        res.send({
          success: true,
          stats: {
            totalProducts,
            acceptedProducts,
            pendingProducts,
            rejectedProducts,
            totalReviews,
            totalUpvotes,
            membership,
            joinDate: user?.createdAt || null
          }
        });
      } catch (error) {
        console.error("Error fetching user stats:", error);
        res.status(500).send({ error: true, message: "Failed to fetch user statistics" });
      }
    });

    // Get user activity
    app.get("/users/activity/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        const { page = 1, limit = 10 } = req.query;
        
        // Check if the requester is the owner of the profile or admin
        if (email !== req.user.email && req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden" });
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get user's recent products
        const recentProducts = await products
          .find({ ownerEmail: email })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Get user's recent reviews
        const recentReviews = await reviews
          .find({ userEmail: email })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Get user's recent payments
        const recentPayments = await payments
          .find({ email })
          .sort({ date: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Combine and sort all activities by date
        const allActivities = [
          ...recentProducts.map(product => ({
            type: "product",
            action: product.status === "accepted" ? "Product approved" : 
                   product.status === "pending" ? "Product submitted" : "Product rejected",
            title: product.name || product.title,
            date: product.createdAt,
            status: product.status,
            id: product._id
          })),
          ...recentReviews.map(review => ({
            type: "review",
            action: "Review posted",
            title: `Review for ${review.productName || "Product"}`,
            date: review.createdAt,
            rating: review.rating,
            id: review._id
          })),
          ...recentPayments.map(payment => ({
            type: "payment",
            action: "Payment completed",
            title: payment.productName || "Payment",
            date: payment.date || payment.paidAt,
            amount: payment.amount,
            status: payment.status,
            id: payment._id
          }))
        ].sort((a, b) => new Date(b.date) - new Date(a.date));

        // Get total count for pagination
        const totalProducts = await products.countDocuments({ ownerEmail: email });
        const totalReviews = await reviews.countDocuments({ userEmail: email });
        const totalPayments = await payments.countDocuments({ email });
        const totalActivities = totalProducts + totalReviews + totalPayments;

        res.send({
          success: true,
          activities: allActivities.slice(0, parseInt(limit)),
          pagination: {
            currentPage: parseInt(page),
            totalPages: Math.ceil(totalActivities / parseInt(limit)),
            totalActivities,
            hasNextPage: parseInt(page) * parseInt(limit) < totalActivities,
            hasPrevPage: parseInt(page) > 1
          }
        });
      } catch (error) {
        console.error("Error fetching user activity:", error);
        res.status(500).send({ error: true, message: "Failed to fetch user activity" });
      }
    });

    

    // Product routes
    app.post("/products", verifyJWT, async (req, res) => {
      const data = {
        ...req.body,
        upvotes: 0,
        status: "pending",
        createdAt: new Date(),
        reported: false,
        reportCount: 0,
        reportedUsers: [],
        upvotedUsers: [],
      };
      const result = await products.insertOne(data);
      res.send(result);
    });

    app.get("/products", async (req, res) => {
      const {
        page = 1,
        limit = 6,
        search = "",
        sort = "createdAt",
        status = "accepted",
      } = req.query;
    
      const skip = (parseInt(page) - 1) * parseInt(limit);
    
      const query = {
        ...(status !== "all" ? { status } : {}),
        ...(search ? { tags: { $regex: search, $options: "i" } } : {}),
      };
    
      const result = await products
        .find(query)
        .sort({ [sort]: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray();
    
      // This is the important part for pagination!
      const total = await products.countDocuments(query);
    
      res.send({
        data: result,
        total,
      });
    });
    
    app.get("/products/reported", verifyJWT, async (req, res) => {
      try {
        const productsReported = await products.find({ reported: true }).toArray();
        res.send(productsReported);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });


    app.get("/products/:id", async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });
    
      const product = await products.findOne({ _id: objectId });
      if (!product)
        return res.status(404).send({ error: true, message: "Product not found" });
    
      res.send(product);
    });

    app.get("/products/users/:email", verifyJWT, async (req, res) => {
      const userProducts = await products.find({ ownerEmail: req.params.email }).toArray();
      res.send(userProducts);
    });

    app.get("/products/review-queue", verifyJWT, async (_, res) => {
      const reviewQueue = await products.find().sort({ createdAt: -1 }).toArray();
      res.send(reviewQueue);
    });

    app.patch("/products/upvote/:id", verifyJWT, async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const userEmail = req.user.email;
      const product = await products.findOne({ _id: objectId });
      if (!product)
        return res.status(404).send({ error: true, message: "Product not found" });

      const alreadyUpvoted = product.upvotedUsers?.includes(userEmail);

      const update = alreadyUpvoted
        ? { $inc: { upvotes: -1 }, $pull: { upvotedUsers: userEmail } }
        : { $inc: { upvotes: 1 }, $addToSet: { upvotedUsers: userEmail } };

      await products.updateOne({ _id: objectId }, update);

      res.send({ updated: true, upvoted: !alreadyUpvoted });
    });

    app.patch("/products/status/:id", verifyJWT, async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const result = await products.updateOne(
        { _id: objectId },
        { $set: { status: req.body.status } }
      );
      res.send(result);
    });

    app.patch("/products/feature/:id", verifyJWT, async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const product = await products.findOne({ _id: objectId });
      if (!product)
        return res.status(404).send({ error: true, message: "Product not found" });

      const result = await products.updateOne(
        { _id: objectId },
        { $set: { isFeatured: !product.isFeatured } }
      );
      res.send(result);
    });
    app.put("/products/:id", verifyJWT, async (req, res) => {
      const productId = req.params.id;
      const updatedData = req.body;
    
      try {
        const result = await products.updateOne(
          { _id: new ObjectId(productId) },
          { $set: updatedData }
        );
    
        if (result.modifiedCount > 0) {
          res.send({ success: true, message: "Product updated successfully." });
        } else {
          res.send({ success: false, message: "No changes were made or product not found." });
        }
      } catch (error) {
        res.status(500).send({ success: false, message: "Update failed.", error });
      }
    });

    // Report product
    app.post("/products/report/:id", verifyJWT, async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const userEmail = req.user.email;
      const product = await products.findOne({ _id: objectId });
      if (!product)
        return res.status(404).send({ error: true, message: "Product not found" });

      const alreadyReported = product.reportedUsers?.includes(userEmail);
      const currentCount = product.reportCount || 0;
      const newReportCount = alreadyReported ? currentCount - 1 : currentCount + 1;

      let update;
      if (alreadyReported) {
        update = {
          $inc: { reportCount: -1 },
          $pull: { reportedUsers: userEmail },
        };
        if (newReportCount <= 0) {
          update.$set = { reported: false };
        }
      } else {
        update = {
          $inc: { reportCount: 1 },
          $addToSet: { reportedUsers: userEmail },
          $set: { reported: true },
        };
      }

      await products.updateOne({ _id: objectId }, update);

      const updatedProduct = await products.findOne({ _id: objectId });

      res.send({ updated: true, reported: !alreadyReported, product: updatedProduct });
    });


    // Delete product
    app.delete("/products/:id", verifyJWT, async (req, res) => {
      const objectId = createObjectId(req.params.id);
      if (!objectId)
        return res.status(400).send({ error: true, message: "Invalid ID format" });

      const result = await products.deleteOne({ _id: objectId });
      res.send(result);
    });

    // Reviews
    app.post("/reviews", verifyJWT, async (req, res) => {
      const result = await reviews.insertOne({ ...req.body, createdAt: new Date() });
      res.send(result);
    });

    app.get("/reviews/:productId", async (req, res) => {
      const result = await reviews.find({ productId: req.params.productId }).toArray();
      res.send(result);
    });

    // 📦 COUPONS API

// ➕ Create a Coupon
app.post("/coupons", verifyJWT, async (req, res) => {
  const { code, discountAmount, discountType, expiryDate } = req.body;

  if (!code || !discountAmount || !expiryDate) {
    return res.status(400).send({
      error: true,
      message: "Coupon code, discount amount, and expiry date are required",
    });
  }

  try {
    const result = await coupons.insertOne({
      code,
      discountAmount: parseFloat(discountAmount),
      discountType: discountType || "flat", // flat or percent
      expiryDate: new Date(expiryDate),
      isActive: true, // required for validation
      createdAt: new Date(),
    });

    res.send(result);
  } catch (error) {
    console.error("Create coupon error:", error);
    res.status(500).send({ error: true, message: "Failed to create coupon" });
  }
});


// 📥 Get All Valid Coupons
app.get("/coupons", async (_, res) => {
  try {
    const today = new Date();
    const validCoupons = await coupons
      .find({ expiryDate: { $gte: today }, isActive: true })
      .sort({ expiryDate: 1 }) // soonest expiry first
      .toArray();

    res.send(validCoupons);
  } catch (error) {
    console.error("Fetch coupons error:", error);
    res.status(500).send({ error: true, message: "Failed to fetch coupons" });
  }
});


// ✏️ Update Coupon by ID
app.put("/coupons/:id", verifyJWT, async (req, res) => {
  const objectId = createObjectId(req.params.id);
  if (!objectId) {
    return res.status(400).send({ error: true, message: "Invalid coupon ID format" });
  }

  try {
    const updateDoc = {
      $set: {
        ...req.body,
        updatedAt: new Date(),
      },
    };

    if (req.body.expiryDate) {
      updateDoc.$set.expiryDate = new Date(req.body.expiryDate);
    }

    const result = await coupons.updateOne({ _id: objectId }, updateDoc);
    res.send(result);
  } catch (error) {
    console.error("Update coupon error:", error);
    res.status(500).send({ error: true, message: "Failed to update coupon" });
  }
});


// ❌ Delete Coupon by ID
app.delete("/coupons/:id", verifyJWT, async (req, res) => {
  const objectId = createObjectId(req.params.id);
  if (!objectId) {
    return res.status(400).send({ error: true, message: "Invalid coupon ID format" });
  }

  try {
    const result = await coupons.deleteOne({ _id: objectId });
    res.send(result);
  } catch (error) {
    console.error("Delete coupon error:", error);
    res.status(500).send({ error: true, message: "Failed to delete coupon" });
  }
});


// ✅ Validate Coupon Code (for users to apply)
app.post("/coupons/validate", async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).send({ error: true, message: "Coupon code is required" });
  }

  try {
    const today = new Date();
    const coupon = await coupons.findOne({
      code: new RegExp(`^${code}$`, "i"),
      isActive: true,
      expiryDate: { $gte: today },
    });

    if (!coupon) {
      return res.status(404).send({ error: true, message: "Invalid or expired coupon" });
    }

    res.send({
      success: true,
      discountAmount: coupon.discountAmount,
      discountType: coupon.discountType || "flat",
      couponCode: coupon.code,
      expiresOn: coupon.expiryDate,
    });
  } catch (error) {
    console.error("Coupon validation error:", error);
    res.status(500).send({ error: true, message: "Failed to validate coupon" });
  }
});





    // Stripe Payment Intent
    app.post("/create-payment-intent", async (req, res) => {
      try {
        const amount = Number(req.body.amount);
        if (!amount || amount <= 0) {
          return res.status(400).send({ error: "Invalid amount" });
        }
    
        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(amount * 100),
          currency: "usd",
          payment_method_types: ["card"],
        });
    
        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (err) {
        console.error("Stripe error:", err.message);
        res.status(500).send({ error: "Payment intent creation failed" });
      }
    });
    
    app.post("/payments", verifyJWT, async (req, res) => {
      try {
        // Validate required fields (optional but recommended)
        const { email, amount, paymentIntentId } = req.body;
        if (!email || !amount || !paymentIntentId) {
          return res.status(400).send({ error: "Missing payment data" });
        }
    
        // Insert payment record into DB
        const result = await payments.insertOne({
          email,
          amount,
          paymentIntentId,
          paidAt: new Date(),
        });
    
        res.send(result);
      } catch (err) {
        console.error("Payments insert error:", err);
        res.status(500).send({ error: "Failed to record payment" });
      }
    });

    // SSL Commerz

     // Payment Success
     app.post('/api/payment/success/:tranId', async (req, res) => {
      const tranId = req.params.tranId;

      const result = await payments.updateOne(
        { transactionId: tranId },
        { $set: { status: 'Success' } }
      );

      if (result.modifiedCount > 0) {
        res.redirect(`http://localhost:5173/payment/success?tranId=${tranId}`);
      } else {
        res.send('Payment success, but DB not updated.');
      }
    });

     // Payment Fail
     app.post('/api/payment/fail/:tranId', async (req, res) => {
      const tranId = req.params.tranId;

      await payments.updateOne(
        { transactionId: tranId },
        { $set: { status: 'Failed' } }
      );

      res.redirect(`http://localhost:5173/payment/fail?tranId=${tranId}`);
    });

    // Cancel
    app.post('/api/payment/cancel/:tranId', async (req, res) => {
      const tranId = req.params.tranId;

      await payments.updateOne(
        { transactionId: tranId },
        { $set: { status: 'Cancelled' } }
      );

      res.redirect(`http://localhost:5173/payment/cancel?tranId=${tranId}`);
    });

    // Optional: Check payment by ID
    app.get('/api/payment/:tranId', async (req, res) => {
      const tranId = req.params.tranId;
      const result = await payments.findOne({ transactionId: tranId });
      res.send(result);
    });


    // Admin Dashboard Endpoints
    
    // 1. GET /admin/stats - Main admin statistics
    app.get("/admin/stats", verifyJWT, async (req, res) => {
      try {
        // Check if the user role is admin
        if (req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden: Admins only" });
        }

        // Get current date and month start
        const now = new Date();
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
        const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);

        // Basic counts
        const totalUsers = await users.countDocuments();
        const totalProducts = await products.countDocuments();
        
        // Calculate total views (sum of viewCount from all products)
        const allProducts = await products.find({}).toArray();
        const totalViews = allProducts.reduce((sum, product) => sum + (product.viewCount || 0), 0);
        
        // Calculate total revenue from payments
        const allPayments = await payments.find({ status: "Success" }).toArray();
        const totalRevenue = allPayments.reduce((sum, payment) => sum + (payment.amount || 0), 0);
        
        // Monthly growth calculation
        const currentMonthUsers = await users.countDocuments({ createdAt: { $gte: monthStart } });
        const lastMonthUsers = await users.countDocuments({ createdAt: { $gte: lastMonthStart, $lt: monthStart } });
        const monthlyGrowth = lastMonthUsers > 0 ? ((currentMonthUsers - lastMonthUsers) / lastMonthUsers * 100).toFixed(2) : 0;
        
        // Pending verifications (products pending review)
        const pendingVerifications = await products.countDocuments({ status: "pending" });
        
        // Active users (users with activity in last 30 days)
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        const activeUsers = await users.countDocuments({ 
          $or: [
            { "lastActivity": { $gte: thirtyDaysAgo } },
            { "createdAt": { $gte: thirtyDaysAgo } }
          ]
        });
        
        // New users this month
        const newUsersThisMonth = await users.countDocuments({ createdAt: { $gte: monthStart } });

        res.send({
          success: true,
          stats: {
            totalUsers,
            totalProducts,
            totalViews,
            totalRevenue,
            monthlyGrowth: parseFloat(monthlyGrowth),
            pendingVerifications,
            activeUsers,
            newUsersThisMonth
          }
        });
      } catch (error) {
        console.error("Error fetching admin stats:", error);
        res.status(500).send({ error: true, message: "Failed to fetch admin statistics" });
      }
    });

    // 2. GET /admin/users/stats - User statistics
    app.get("/admin/users/stats", verifyJWT, async (req, res) => {
      try {
        // Check if the user role is admin
        if (req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden: Admins only" });
        }

        const verifiedUsers = await users.countDocuments({ membership: "verified" });
        const unverifiedUsers = await users.countDocuments({ 
          $or: [
            { membership: { $exists: false } },
            { membership: { $ne: "verified" } }
          ]
        });
        const premiumUsers = await users.countDocuments({ membership: "premium" });
        const freeUsers = await users.countDocuments({ 
          $or: [
            { membership: { $exists: false } },
            { membership: "basic" }
          ]
        });

        res.send({
          success: true,
          stats: {
            verifiedUsers,
            unverifiedUsers,
            premiumUsers,
            freeUsers
          }
        });
      } catch (error) {
        console.error("Error fetching admin user stats:", error);
        res.status(500).send({ error: true, message: "Failed to fetch user statistics" });
      }
    });

    // 3. GET /admin/products/stats - Product statistics
    app.get("/admin/products/stats", verifyJWT, async (req, res) => {
      try {
        // Check if the user role is admin
        if (req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden: Admins only" });
        }

        const publishedProducts = await products.countDocuments({ status: "accepted" });
        const pendingReview = await products.countDocuments({ status: "pending" });
        const rejectedProducts = await products.countDocuments({ status: "rejected" });

        // Get top categories
        const categoryStats = await products.aggregate([
          { $match: { status: "accepted" } },
          { $group: { _id: "$category", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ]).toArray();

        const totalPublished = publishedProducts;
        const topCategories = categoryStats.map(cat => ({
          name: cat._id || "Uncategorized",
          count: cat.count,
          percentage: totalPublished > 0 ? ((cat.count / totalPublished) * 100).toFixed(2) : 0
        }));

        res.send({
          success: true,
          stats: {
            publishedProducts,
            pendingReview,
            rejectedProducts,
            topCategories
          }
        });
      } catch (error) {
        console.error("Error fetching admin product stats:", error);
        res.status(500).send({ error: true, message: "Failed to fetch product statistics" });
      }
    });

    // 4. GET /admin/activity - Admin activity feed
    app.get("/admin/activity", verifyJWT, async (req, res) => {
      try {
        // Check if the user role is admin
        if (req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden: Admins only" });
        }

        const { page = 1, limit = 20 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get recent activities from different collections
        const recentProducts = await products
          .find({})
          .sort({ createdAt: -1 })
          .limit(parseInt(limit))
          .toArray();

        const recentUsers = await users
          .find({})
          .sort({ createdAt: -1 })
          .limit(parseInt(limit))
          .toArray();

        const recentPayments = await payments
          .find({})
          .sort({ date: -1 })
          .limit(parseInt(limit))
          .toArray();

        // Combine and format activities
        const allActivities = [
          ...recentProducts.map(product => ({
            id: product._id.toString(),
            type: "product",
            title: product.name || product.title || "New Product",
            description: `Product ${product.status} by ${product.ownerEmail || "Unknown"}`,
            timestamp: product.createdAt,
            icon: product.status === "accepted" ? "✅" : 
                  product.status === "pending" ? "⏳" : "❌"
          })),
          ...recentUsers.map(user => ({
            id: user._id.toString(),
            type: "user",
            title: "New User Registration",
            description: `${user.name || user.email} joined the platform`,
            timestamp: user.createdAt,
            icon: "👤"
          })),
          ...recentPayments.map(payment => ({
            id: payment._id.toString(),
            type: "payment",
            title: "Payment Completed",
            description: `Payment of ${payment.amount} by ${payment.name || payment.email}`,
            timestamp: payment.date || payment.paidAt,
            icon: "💰"
          }))
        ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Apply pagination
        const paginatedActivities = allActivities.slice(skip, skip + parseInt(limit));

        // Get total count for pagination
        const totalProducts = await products.countDocuments();
        const totalUsers = await users.countDocuments();
        const totalPayments = await payments.countDocuments();
        const totalActivities = totalProducts + totalUsers + totalPayments;

        res.send({
          success: true,
          activities: paginatedActivities,
          pagination: {
            currentPage: parseInt(page),
            totalPages: Math.ceil(totalActivities / parseInt(limit)),
            totalActivities,
            hasNextPage: parseInt(page) * parseInt(limit) < totalActivities,
            hasPrevPage: parseInt(page) > 1
          }
        });
      } catch (error) {
        console.error("Error fetching admin activity:", error);
        res.status(500).send({ error: true, message: "Failed to fetch admin activity" });
      }
    });

    // Legacy admin statistics endpoint (keeping for backward compatibility)
    app.get("/admin/statistics", verifyJWT, async (req, res) => {
      try {
        // Check if the user role is admin
        if (req.user.role !== "admin") {
          return res.status(403).send({ error: true, message: "Forbidden: Admins only" });
        }
    
        const totalProducts = await products.countDocuments();
        const accepted = await products.countDocuments({ status: "accepted" });
        const pending = await products.countDocuments({ status: "pending" });
        const totalReviews = await reviews.countDocuments();
        const totalUsers = await users.countDocuments();
    
        res.send({
          totalProducts,
          accepted,
          pending,
          totalReviews,
          totalUsers,
        });
      } catch (error) {
        console.error("Error fetching admin statistics:", error);
        res.status(500).send({ error: true, message: "Failed to fetch statistics" });
      }
    });
    
    // Root route
    app.get("/", (_, res) => res.send("✅ AppOrbit Backend Running"));
  } catch (err) {
    console.error("❌ Backend Init Error:", err);
  }
}

run().catch(console.error);

app.listen(port, () => console.log(`🌐 Server running on port ${port}`));

// Graceful shutdown on SIGINT
process.on("SIGINT", async () => {
  console.log("\n🛑 Shutting down...");
  process.exit();
});
