var express = require("express");
// const { stringify } = require("flatted");
// const bodyParser = require("body-parser");
var router = express.Router();
// const OpenAI = require("openai");
// const https = require("https");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const Users = require("../models/Users");
const jwt = require("jsonwebtoken");
const JWT_SECRET = "your_secret_key"; // This should be stored securely and not hardcoded in production
const TOKEN_EXPIRATION = "1h"; // Token expires in 1 hour
const bcrypt = require("bcryptjs");
const SkillSets = require("../models/SkillSets");
const Periods = require("../models/Periods");
const TemplateCategories = require("../models/TemplateCategories");
const Templates = require("../models/Templates");
const Projects = require("../models/Projects");
// const BiddingPrice = require("../models/Biddingprice");
const Payments = require("../models/Payments");
// const { exec } = require("child_process");
const moment = require("moment");
const mongoose = require("mongoose");
const Biddingprice = require("../models/Biddingprice");
const filePath = path.join(__dirname, "exported_data.json");
const crypto = require("crypto"); // Import the crypto module for password generation

const allSkills = fs.existsSync(filePath)
  ? JSON.parse(fs.readFileSync(filePath, "utf-8"))
  : [];

const adminInfoMiddleware = (req, res, next) => {
  if (req.session.user) {
    console.log(req.session);
    // If admin session exists, store admin email and phone in session
    res.locals.username = req.session.user.username;
    res.locals.adminEmail = req.session.user.adminEmail;
    res.locals.adminPhone = req.session.user.adminPhone;
    res.locals.adminSkype = req.session.user.adminSkype;
    res.locals.adminTelegram = req.session.user.adminTelegram;
  }
  next();
};

// Middleware to check if the user is authenticated and their session status
// const sessionChecker = (req, res, next) => {
//   if (req.session && req.session.user) {
//     const subscriptionEndDate = moment(req.session.user.subscriptionEndDate);
//     const currentTime = moment();

//     if (req.session.user.isLocked === false) {
//       if (subscriptionEndDate.isAfter(currentTime)) {
//         res.locals.user = req.session.user;
//         next();
//       } else {
//         res.redirect("/myBidsBlock");
//       }
//     } else {
//       res.redirect("/locked");
//     }
//   } else {
//     res.redirect("/login");
//   }
// };
const sessionChecker = (req, res, next) => {
  console.log("Checking session...");

  if (req.session && req.session.user) {
    console.log("Session exists:", req.session.user);
    const subscriptionEndDate = moment(req.session.user.subscriptionEndDate);
    const currentTime = moment();

    if (!req.session.user.isLocked) {
      if (subscriptionEndDate.isAfter(currentTime)) {
        res.locals.user = req.session.user;
        return next();
      } else {
        console.log("Subscription expired.");
        return res.redirect("/myBidsBlock");
      }
    } else {
      console.log("User is locked.");
      return res.redirect("/locked");
    }
  } else {
    console.log("No session or user not logged in.");
    return res.redirect("/login");
  }
};
const isAdmin = (req, res, next) => {
  // Check if user is logged in and isAdmin is true
  if (req.session.admin && req.session.admin.isAdmin) {
    res.locals.user = req.session.admin;
    // User is an admin, proceed to the next middleware or route handler
    next();
  } else {
    // User is not an admin, redirect to login page or display an error
    req.flash(
      "error",
      "Access denied. You must be an admin to access this page."
    );
    res.redirect("/login"); // Redirect to login page
  }
};

function isLoggedIn(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.status(401).send("You are not logged in");
  }
}

function isNotLoggedIn(req, res, next) {
  if (!req.session.user) {
    next();
  } else {
    res.status(401).send("You are already logged in");
    res.redirect("/myBids");
  }
}
router.use(adminInfoMiddleware);
/* GET home page. */
router.get("/", async function (req, res, next) {
  const payments = await Payments.find();
  console.log("payments : ", payments[0]);
  res.render("index", { title: "Express", payments });
});

router.get("/dashboard", sessionChecker, function (req, res, next) {
  res.redirect("/myBids");
});

router.get("/settings", sessionChecker, function (req, res, next) {
  res.render("settings", { title: "Express" });
});

router.get("/login", function (req, res, next) {
  res.render("login", {
    title: "Express",
    error: req.flash("error" || undefined),
  });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  // console.log("here is user password---->",password)
  try {
    const user = await Users.findOne({ username: username });
    if (!user) {
      req.flash("error", "No user found.");
      res.redirect("/login");
      return;
    }

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      req.flash("error", "Invalid credentials.");
      res.redirect("/login");
      return;
    }

    if (user.isAdmin) {
      // Create admin object

      const admin = {
        _id: user._id,
        id: user.id,
        username: user.username,
        location: user.location,
        primary_currency: user.primary_currency,
        primary_language: user.primary_language,
        timezone: user.timezone,
        email: user.email,
        phone: user.phone,
        role: user.role,
        tokenExpirationDate: user.tokenExpirationDate,
        access_token: user.access_token,
        refresh_token: user.refresh_token,
        skills: user.skills,
        excluded_skills: user.excluded_skills,
        excluded_countries: user.excluded_countries,
        bidsAllow: user.bidsAllow,
        trial: user.trial,
        autoBid: user.autoBid,
        timeInterval: user.timeInterval,
        timeLimit: user.timeLimit,
        bidsLimit: user.bidsLimit,
        subscriptionType: user.subscriptionType,
        subscriptionStartDate: user.subscriptionStartDate,
        subscriptionEndDate: user.subscriptionEndDate,
        isLocked: user.isLocked,
        password: user.password,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        isAdmin: true,
        // Add any other admin-specific properties if needed
      };

      // Save admin session
      req.session.admin = admin;
      (req.session.adminEmail = user.email),
        (req.session.adminPhone = user.phone),
        (req.session.adminSkype = user.skype),
        (req.session.adminTelegram = user.telegram),
        console.log("Admin session created");
      req.flash("success", "Login successful!");
      return res.redirect("/admin/dashboard");
    }
    const adminUser = await Users.findOne({
      // username: username,
      isAdmin: true,
    });
    // console.log("adminUser", adminUser);
    // If passwords match, save user session
    req.session.user = {
      ...user,
      adminEmail: adminUser.email,
      adminPhone: adminUser.phone,
      adminSkype: adminUser.skype,
      adminTelegram: adminUser.telegram,
    };
    const sanitizedUser = {
      ...user._doc, // Assuming user is your existing user object
      adminEmail: adminUser.email,
      adminPhone: adminUser.phone,
      adminSkype: adminUser.skype,
      adminTelegram: adminUser.telegram,
    };

    // Remove specific properties if needed
    delete sanitizedUser.$__;
    delete sanitizedUser.$isNew;

    // Assign the sanitized user to the session
    req.session.user = sanitizedUser;
    // console.log("user session is", req.session.user);

    req.flash("success", "Login successful!");

    return res.redirect("/myBids");
  } catch (error) {
    console.log("error", error);
    req.flash("error", "Server error occurred.");
    res.redirect("/login");
  }
});

router.get("/signup", async function (req, res, next) {
  const payments = await Payments.find();
  res.render("signup", { payments: payments[0], title: "Express" });
});

router.get("/create-password/:token", function (req, res, next) {
  res.render("create-password", {
    token: req.params.token,
    messages: req.flash("error"),
  });
});

router.post("/create-password", async function (req, res, next) {
  const { token, password, confirmPassword, email, phoneNo } = req.body;

  // Step 1: Verify the token
  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Ensure JWT_SECRET is safely stored and accessed
    const userId = decoded.userId;

    // Step 2: Validate the passwords
    if (!email || !phoneNo) {
      req.flash("error", "Enter credentials ");
      return res.redirect("/create-password/" + token);
    }
    // Step 2: Validate the passwords
    if (password !== confirmPassword) {
      req.flash("error", "Passwords do not match");
      return res.redirect("/create-password/" + token);
    }

    // Step 3: Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Step 4: Update the User model
    const user = await Users.findById(userId);
    if (!user.isAdmin) {
      const adminUser = await Users.findOne({ isAdmin: true });

      // If passwords match, save user session
      req.session.user = {
        ...user,
        adminEmail: !adminUser?.email ? email : adminUser?.email,
        adminPhone: !adminUser?.phone ? phoneNo : adminUser?.phone,
        adminSkype: adminUser?.skype,
        adminTelegram: adminUser?.telegram,
      };
      const sanitizedUser = {
        ...user._doc, // Assuming user is your existing user object
        adminEmail: !adminUser?.email ? email : adminUser?.email,
        adminPhone: !adminUser?.phone ? phoneNo : adminUser?.phone,
        adminSkype: adminUser?.skype,
        adminTelegram: adminUser?.telegram,
      };

      // Remove specific properties if needed
      delete sanitizedUser.$__;
      delete sanitizedUser.$isNew;

      // Assign the sanitized user to the session
      req.session.user = sanitizedUser;
    }

    if (!user) {
      req.flash("error", "User not found");
      return res.redirect("/create-password/" + token);
    }
    user.email = email;
    user.phone = phoneNo;
    user.password = hashedPassword;
    await user.save();
    delete user.password;
    // req.session.user = user;
    res.locals.adminEmail = req.session.user.adminEmail;
    res.locals.adminPhone = req.session.user.adminPhone;
    res.locals.adminSkype = req.session.user.adminSkype;
    res.locals.adminTelegram = req.session.user.adminTelegram;

    res.locals.username = req.session.user.username;

    req.flash("success", "Password has been set successfully.");
    res.redirect("/myBids");
  } catch (error) {
    console.log("here,", error);
    req.flash("error", "Invalid or expired token.");
    res.redirect("/create-password/" + token);
  }
});

// Helper function to generate a random state parameter
function generateRandomState() {
  return Math.random().toString(36).substring(7);
}

// Users who hit this endpoint will be redirected to the authorization prompt
router.get("/authorize", (req, res) => {
  const state = generateRandomState();
  const oauthUri = "https://accounts.freelancer.com/oauth/authorize";
  const clientId = process.env.clientId;
  const redirectUri = process.env.redirectUri;

  const prompt = "select_account consent";
  const advancedScopes = "1 2 3 6";
  const authorizationUrl = `${oauthUri}?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=basic&prompt=${prompt}&advanced_scopes=${advancedScopes}&state=${state}`;
  res.redirect(authorizationUrl);
});

router.get("/freelancer/callback", async (req, res) => {
  let code = req.query.code;
  const clientSecret = process.env.clientSecret;
  const clientId = process.env.clientId;
  const redirectUri = process.env.redirectUri;
  const url = "https://accounts.freelancer.com/oauth/token";

  const payload = `grant_type=authorization_code&code=${code}&client_id=${clientId}&client_secret=${clientSecret}&redirect_uri=${redirectUri}`;
  console.log("here 4", code);
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };

  try {
    let response = await axios.post(url, payload, { headers });

    console.log("here 5", response);

    let data = await getSelfData(response.data);
    console.log("here is data=====> : ", data);

    let checkUser = await Users.findOne({ username: data.user.username });
    if (checkUser && checkUser.password) {
      return res.render("alreadyRegistered");
    }
    if (data.status) {
      req.session.user = {
        id: data.user._id,
        username: data.user.username,
      };
      // req.session.user = data.user
      res.redirect(`/create-password/${data.token}`);
    } else {
      req.flash("error", "Error Occured. Try again later.");
      res.redirect("/login");
    }
  } catch (error) {
    req.flash("error", "Error Occured. Try again later.");
    console.log(error);
    res.redirect("/login");
  }
});

const getSelfData = async (data) => {
  console.log("here in getSelfData function");
  const url =
    "https://freelancer.com/api/users/0.1/self?preferred_details=true";
  const url2 = "https://freelancer.com/api/users/0.1/self?jobs=true";

  const headers = { "freelancer-oauth-v1": data.access_token,'Accept': 'application/json',
        'User-Agent': 'axios/1.7.9', };

  try {
    const response = await axios.get(url, { headers });
    const response2 = await axios.get(url2, { headers });

    if (response.data && response.data.result) {
      const userResult = response.data.result;
      const jobsResult = response2.data?.result?.jobs || [];
      const expiresIn = data.expires_in; // token expires in seconds
      const currentDate = new Date();
      const expirationDate = new Date(currentDate.getTime() + expiresIn * 1000);

      const existingUser = await Users.findOne({
        username: userResult.username,
      });

      if (existingUser) {
        const jobNames = jobsResult.map((job) => String(job.name));
        existingUser.skills = jobNames;
        existingUser.access_token = data.access_token;
        existingUser.refresh_token = data.refresh_token;
        existingUser.tokenExpirationDate = expirationDate;

        if (userResult.avatar_cdn || userResult.avatar_large_cdn) {
          existingUser.profilePicture =
            userResult.avatar_cdn || userResult.avatar_large_cdn;
        }
        await existingUser.save();
        return { status: true, user: existingUser };
      } else {
        const jobNames = jobsResult.map((job) => String(job.name));
        const pp = userResult.avatar_cdn || userResult.avatar_large_cdn;

        const user = new Users({
          ...userResult,
          skills: jobNames,
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          tokenExpirationDate: expirationDate,
          role: "freelancer",
          trial: true,
          bidsAllow: 10,
          subscriptionStartDate: currentDate.toISOString(),
          subscriptionEndDate: new Date(
            currentDate.setDate(currentDate.getDate() + 3)
          ).toISOString(),
        });

        if (pp) user.profilePicture = pp;

        const savedUser = await user.save();
        return { status: true, user: savedUser };
      }
    }
    return { status: false, user: undefined };
  } catch (error) {
    console.error("Error in getSelfData:", error);
    return { status: false, user: undefined };
  }
};

// router.get("/myBids", sessionChecker, async (req, res) => {
//   // const url = "https://www.freelancer-sandbox.com/api/users/0.1/self/jobs/";
//   // let id = req.session.user._id;
//   // let user = await Users.findOne({ _id: id });
//   // // let accessToken = user.access_token;
//   // let accessToken = "UnkxqQ39gqRWYAUZWVmspVZiK0UbqY";
//   // console.log("accessToken--->",accessToken)
//   // const headers = { "freelancer-oauth-v1": accessToken };
//   // let userSkills = req.session.user.skills;
//   // const userSkillsWithValue = userSkills
//   //   .map((skill) => {
//   //     const matchedSkill = allSkills.find((s) => s.tag === skill);
//   //     return matchedSkill ? { skill, value: matchedSkill.value } : null;
//   //   })
//   //   .filter(Boolean);
//   // const userSkillValues = userSkillsWithValue.map((skill) => skill.value);

//   // const params = {
//   //   jobs: userSkillValues,
//   // };

//   // try {
//   //   const response = await axios.post(url, {
//   //     params: params,
//   //     headers: headers,
//   //   });
//   //   console.log("here is response data from jobs----->", response.data.request_id);
//   //   const reqId=response.data.request_id;
//   //   req.session.request_id=reqId
//   // } catch (error) {
//   //   // Handle errors
//   //   console.error("Error fetching data:", error);
//   //   res.status(500).send("An error occurred while fetching data.");
//   // }
//   let userId=req.session.user._id
//   let user=await Users.findById(userId);
//   if (user) {
//     let userAutoBid = user.autoBid ? "ON" : "Off";
//     console.log("User AutoBidding is: ", userAutoBid);
//     res.render("myBids", { userAutoBid });
//   } else {
//     console.log("User not found");
//     // Handle this case accordingly
//   }
// } catch ((err) {
//   console.error("Error finding user:", err);
//   // Handle error
// });
// //   const url = 'https://www.freelancer-sandbox.com/api/users/0.1/self/jobs/';

// // // Assuming you have already retrieved the access token, user ID, and user skills
// // const id = req.session.user._id;
// // const user = await Users.findOne({ _id: id });
// // const accessToken = user.access_token;
// // const userSkills = req.session.user.skills;

// // // Assuming allSkills is available and contains skill values
// // const userSkillsWithValue = userSkills.map((skill) => {
// //   const matchedSkill = allSkills.find((s) => s.tag === skill);
// //   return matchedSkill ? { skill, value: matchedSkill.value } : null;
// // }).filter(Boolean);

// // const userSkillValues =  userSkillsWithValue
// // .map((skill) => parseInt(skill.value))
// // .slice(0, 9); // Limits to the first 20 elements
// //   console.log("heree are skills------>",userSkillValues)
// // const headers = {
// //   'Content-Type': 'application/json',
// //   'freelancer-oauth-v1': accessToken
// // };

// // fetch(url, {
// //   method: 'POST',
// //   headers: headers,
// //   body: JSON.stringify({ "jobs[]": userSkillValues })
// // })
// //   .then(response => response.json())
// //   .then(data => {

// //     console.log('Response:', data);
// //   })
// //   .catch(error => {
// //     console.error('Error:', error);
// //   });
// });
async function getProjectsCountForUserLast7Days(userId) {
  const today = new Date();
  const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000); // Subtract 7 days in milliseconds

  // console.log("Today:", today.toISOString().split("T")[0]);
  // console.log("Seven days ago:", sevenDaysAgo.toISOString().split("T")[0]);

  try {
    const projectCounts = [];

    for (let i = 0; i < 7; i++) {
      const startDate = new Date(
        today.getTime() - (i + 1) * 24 * 60 * 60 * 1000
      ); // Subtract i days from today
      const endDate = new Date(today.getTime() - i * 24 * 60 * 60 * 1000); // Subtract i-1 days from today

      const projects = await Projects.find({
        time: { $gte: startDate, $lt: endDate },
        user: userId,
      });

      const formattedDate = startDate.toISOString().split("T")[0];
      const count = projects.length;

      projectCounts.push({ _id: formattedDate, count });
    }

    // console.log("Project counts:", projectCounts);

    return projectCounts;
  } catch (error) {
    console.error("Error fetching project counts:", error);
    throw error;
  }
}

// Function to fill missing dates with zero counts
function fillMissingDates(projectCounts, startDate, endDate) {
  const result = [];
  let currentDate = new Date(startDate);

  while (currentDate <= endDate) {
    const formattedDate = currentDate.toISOString().split("T")[0];
    const existingEntry = projectCounts.find(
      (entry) => entry._id === formattedDate
    );
    if (existingEntry) {
      result.push(existingEntry);
    } else {
      result.push({ _id: formattedDate, count: 0 });
    }
    currentDate.setDate(currentDate.getDate() + 1);
  }

  return result;
}

router.get("/myBidsBlock", async (req, res) => {
  const pricing = await Payments.find({});

  res.render("myBidsBlock", { pricing });
});

router.get("/myBids", sessionChecker, async (req, res) => {
  try {
    let userId = req.session.user._id;

    let user = await Users.findById(userId);
    // console.log("here is user : ", user);
    let timeInterval = user.timeInterval;
    const pricing = await Payments.find({});
    if (user) {
      let userAutoBid = user.autoBid ? "ON" : "Off";
      // console.log("User AutoBidding is: ", userAutoBid);
      let data = await getProjectsCountForUserLast7Days(userId);
      // console.log("data--->", data);
      // console.log("user id : ", userId);
      let project = await Projects.find({ user: user._id });

      let projectCount = project.length;
      let failedProjectsCount = project.filter(
        (project) => project.status === 1
      ).length;
      let successfulProjectsCount = project.filter(
        (project) => project.status != 1
      ).length;
      let allowedBids = projectCount;
      // console.log("allowedBids--->", allowedBids);
      // console.log("user project counts ", projectCount);
      // console.log("user failedProjectsCount counts ", failedProjectsCount);
      // console.log(
      //   "user successfulProjectsCount counts ",
      //   successfulProjectsCount
      // );
      res.render("myBids", {
        pricing,
        userAutoBid,
        data,
        allowedBids,
        failedProjectsCount,
        successfulProjectsCount,
        timeInterval,
      });
    } else {
      console.log("User not found");
      // Handle this case accordingly
    }
  } catch (err) {
    console.error("Error finding user:", err);
    // Handle error
  }
});
router.get("/autoBidTurnOn", sessionChecker, async (req, res) => {
  try {
    const userId = req.session.user._id;
    const user = await Users.findById(userId);
    // Get the autoBid value from query parameters
    const userAutoBid = req.query.autoBid;
    const redirectUrl = req.query.redirect || "/myBids";
    // Update user's autoBid status based on the query parameter
    if (userAutoBid === "ON") {
      user.autoBid = true;
    } else {
      user.autoBid = false;
      user.bidStartTime = null;
      user.bidEndTime = null;
      user.breakTime = null;
    }

    // Save the updated user object
    await user.save();

    // Log the updated autoBid status
    // console.log("User AutoBidding:", user.autoBid);

    // Further logic based on the user's autoBid status
    // console.log("123: ", redirectUrl);
    res.redirect(redirectUrl);
  } catch (err) {
    console.error("Error updating autoBid status:", err);
    // Handle error
    res.status(500).send("Error updating autoBid status");
  }
});
router.get("/autoBidTurnOnTimeSetting", sessionChecker, async (req, res) => {
  try {
    const userId = req.session.user._id;
    const user = await Users.findById(userId);
    // Get the autoBid value from query parameters
    const userAutoBid = req.query.autoBid;

    // Update user's autoBid status based on the query parameter
    if (userAutoBid === "ON") {
      user.autoBid = true;
    } else {
      user.autoBid = false;
      user.bidStartTime = "";
      user.bidEndTime = "";
      user.breakTime = "";
    }

    // Save the updated user object
    await user.save();

    // Log the updated autoBid status
    // console.log("User AutoBidding:", user.autoBid);

    // Further logic based on the user's autoBid status

    res.redirect("/timeSetting");
  } catch (err) {
    console.error("Error updating autoBid status:", err);
    // Handle error
    res.status(500).send("Error updating autoBid status");
  }
});
function isIntervalHit(pastDate, timeInterval) {
  // Convert pastDate to a Date object
  const pastDateTime = new Date(pastDate);

  // Calculate the future date by adding the time interval (in milliseconds)
  const futureDateTime = new Date(
    pastDateTime.getTime() + timeInterval * 60000
  ); // Convert minutes to milliseconds

  // Get the current date and time
  // const currentDateTime = new Date();

  // Check if the future date is less than the current date
  return futureDateTime > pastDateTime;
}

router.get("/test2", sessionChecker, async (req, res) => {
  try {
    // Get user ID from session
    const userId = req.session.user._id;

    // Fetch user details using the user ID
    let user = await Users.findById(userId);

    // Extract access token from user details
    let accessToken = user.access_token;

    // Extract excluded skills and excluded countries from user details
    let excludedSkills = user.excluded_skills;
    let excludedCountries = user.excluded_countries;
    let clientPaymentVerified = user.payment_verified;
    let clientEmailVerified = user.email_verified;
    let clientDepositMade = user.deposit_made;
    let minimumBudgetFix = parseInt(user.minimum_budget_fixed);
    let minimumBudgetHourly = parseInt(user.minimum_budget_hourly);

    // Construct headers with access token
    // const headers = { "freelancer-oauth-v1": accessToken };

    let bidsAllowed = user.bidsAllow;
    // console.log("bits allowed are", bidsAllowed);

    while (bidsAllowed > 0) {
      // API endpoint for fetching projects
      const url = "https://freelancer.com/api/projects/0.1/projects/all/";

      // Parameters for the API request
      const params = {
        min_avg_price: 10,
        project_statuses: ["active"],
        full_description: true,
        job_details: true,
        user_details: true,
        location_details: true,
        user_status: true,
        user_reputation: true,
        user_country_details: true,
        user_display_info: true,
        user_membership_details: true,
        user_financial_details: true,
        compact: true,
      };

      // Make request to fetch projects
      const response = await axios.get(url, {
        params: params,
        headers: headers,
      });

      // Process response data
      const responseData = response.data;
      const projects = responseData.result.projects;

      // Extract user details for project owners
      const ownerIds = projects.map((project) => project.owner_id);
      const projectsDetails = await Promise.all(
        ownerIds.map(async (ownerId) => {
          if (!isNaN(ownerId)) {
            const ownerUrl = `https://freelancer.com/api/users/0.1/users/${ownerId}/`;
            const ownerResponse = await axios.get(ownerUrl, {
              jobs: true,
              reputation: true,
              employer_reputation: true,
              reputation_extra: true,
              employer_reputation_extra: true,
              job_ranks: true,
              staff_details: true,
              completed_user_relevant_job_count: true,
              headers: headers,
            });
            return ownerResponse.data.result;
          } else {
            return null;
          }
        })
      );

      // Render projects
      const projects2 = responseData.result.projects.map((project, index) => ({
        projectid: project.id,
        type: project.type,
        description: project.description,
        title: project.title,
        currencyName: project.currency.name,
        currencySign: project.currency.sign,
        bidCount: project.bid_stats.bid_count,
        bidAverage: project.bid_stats.bid_avg,
        jobNames: project.jobs.map((job) => job.name),
        minimumBudget: project.budget.minimum,
        maximumBudget: project.budget.maximum,
        country: project.location.country.flag_url,
        fullName: projectsDetails[index]?.username,
        displayName: projectsDetails[index]?.public_name,
        ownerCountry: projectsDetails[index]?.location?.country?.name,
        payment: projectsDetails[index]?.status?.payment_verified,
        email: projectsDetails[index]?.status?.email_verified,
        deposit_made: projectsDetails[index]?.status?.deposit_made,
        identity_verified: projectsDetails[index]?.status?.identity_verified,
        countryShortName: projectsDetails[index]?.timezone?.country,
      }));

      const filteredProjects2 = projects2.filter((project) => {
        // Convert project's countryShortName to lowercase for case-insensitive comparison
        const projectCountry = project.countryShortName
          ? project.countryShortName.toLowerCase()
          : "";

        // Check if project's countryShortName matches any excluded country (case-insensitive)
        if (
          excludedCountries.some(
            (country) => country.toLowerCase() === projectCountry
          )
        ) {
          return false; // Exclude project
        }

        // Check if project's jobNames include any excluded skill (case-insensitive)
        if (
          project.jobNames.some((skill) =>
            excludedSkills.includes(skill.toLowerCase())
          )
        ) {
          return false; // Exclude project
        }
        // console.log("this is project type---->", project.type);

        // console.log(
        //   "this is project minimum budgete---->",
        //   project.minimumBudget
        // );
        // console.log("this is user minimum budgete---->", minimumBudgetFix);
        // Check if clientPaymentVerified is 'yes'
        if (clientPaymentVerified == "yes" && project.payment == null) {
          return false; // Exclude project
        }

        // Check if clientEmailVerified is 'yes'
        if (clientEmailVerified == "yes" && project.email !== true) {
          return false; // Include project
        }

        // Check if clientDepositMade is 'yes'
        if (clientDepositMade == "yes" && project.deposit_made == null) {
          return false; // Exclude project
        }

        // Additional filters based on project type (fixed or hourly)
        if (
          project.type == "fixed" &&
          project.minimumBudget <= minimumBudgetFix
        ) {
          console.log(
            "heree----->" +
              project.type +
              " project inimum budget " +
              project.minimumBudget +
              " minimum budget " +
              minimumBudgetFix
          );
          return false; // Exclude project
        }

        if (
          project.type == "hourly" &&
          project.minimumBudget <= minimumBudgetHourly
        ) {
          return false; // Exclude project
        }

        return true; // Include project
      });
      // console.log("here is filteredProjects2 --------->", filteredProjects2)
      // console.log("after filter--->", filteredProjects2);
      // console.log("length after filter--->", filteredProjects2.length);
      const description =
        "Hello {{ownerName}} , \n" +
        "We would like to grab this opportunity and will work till you get 100% satisfied with our work.\n" +
        "We are an expert team which has many years of experience in Job Skills.\n" +
        "Please come over chat and discuss your requirement in a detailed way.\n" +
        "Thank You";

      const filteredProjectDetails = filteredProjects2.map((project) => {
        const ownerName = project.fullName || project.displayName || "";
        return {
          projectid: project.projectid,
          bidAverage: project.bidAverage,
          minimumBudget: project.minimumBudget,
          maximumBudget: project.maximumBudget,
          fullName: project.fullName,
          displayName: project.displayName,
          jobNames: project.jobNames,
          description:
            `Hello ${ownerName ? ownerName : "there"}, \n` +
            "We would like to grab this opportunity and will work till you get 100% satisfied with our work.\n" +
            "We are an expert team with many years of experience in Job Skills.\n" +
            "Please come over chat and discuss your requirements in detail.\n" +
            "Thank You",
        };
      });
      const numBids = Math.min(filteredProjectDetails.length, bidsAllowed);

      for (let i = 0; i < numBids; i++) {
        setTimeout(async () => {
          const project = filteredProjectDetails[i];
          // Extract project details
          const {
            projectid,
            minimumBudget,
            maximumBudget,
            description,
            bidAverage,
          } = project;
          let averageBid = parseInt(bidAverage);
          let lowRange = parseInt(req.session.user.lower_bid_range);
          let highRange = parseInt(req.session.user.higher_bid_range);
          const lowerValue = averageBid * (lowRange / 100);
          const higherValue = averageBid * (highRange / 100);
          // console.log("Average Bid:", averageBid);
          // console.log("Low Range:", lowRange);
          // console.log("High Range:", highRange);
          // console.log("here is user value------>", higherValue);
          // console.log("here is user value------>", lowerValue);
          let smallValue = averageBid - lowerValue;
          let largeValue = averageBid + higherValue;
          let randomValue = (
            smallValue +
            Math.random() * (largeValue - smallValue)
          ).toFixed(2);
          // console.log("Random Value:---->", randomValue);
          // console.log("here is high value------>", smallValue);
          // console.log("here is randomValue------>", randomValue);
          // Calculate the bid amount (between minimumBudget and maximumBudget)
          let amount = (minimumBudget + maximumBudget) / 2;
          let bidderid = parseInt(req.session.user.id);
          let projectID = parseInt(projectid);
          let bidMoney = parseFloat(randomValue);
          // Prepare the bid request body
          const bidRequestBody = {
            project_id: projectID,
            bidder_id: bidderid,
            amount: bidMoney,
            period: 3,
            milestone_percentage: 50,
            description: description,
          };

          try {
            // Make the POST request to Freelancer API
            const response = await fetch(
              `https://www.freelancer.com/api/projects/0.1/bids/`,
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "freelancer-oauth-v1": accessToken,
                },
                body: JSON.stringify(bidRequestBody),
              }
            );

            // Parse the JSON response
            const responseData = await response.json();

            // Log response
            // console.log("Bid Response:", responseData);

            if (responseData.status !== "error") {
              // Decrease bidsAllowed by 1 for the user if bid was successful
              bidsAllowed--;
              await Users.updateOne(
                { _id: userId },
                { $set: { bidsAllow: bidsAllowed } }
              );
            }
          } catch (error) {
            console.error("Error occurred while sending bid:", error);
            // Handle error if needed
          }
        }, i * 70000);
      }

      // Output the filtered project details
      // console.log("Filtered Project Details:---------->", filteredProjectDetails);
      return res.status(200).json(filteredProjects2.slice(0, numBids));
    }
  } catch (error) {
    console.error("Error occurred:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

async function fetchProjects(accessToken) {
  const url = "https://freelancer.com/api/projects/0.1/projects/all/";
  const headers = {  'Content-Type': 'application/json',"freelancer-oauth-v1": accessToken };
  const params = {
    min_avg_price: 10,
    project_statuses: ["active"],
    full_description: true,
    job_details: true,
    user_details: true,
    location_details: true,
    user_status: true,
    user_reputation: true,
    user_country_details: true,
    user_display_info: true,
    user_membership_details: true,
    user_financial_details: true,
    compact: true,
  };
  const response = await axios.get(url, { params, headers });
  return response.data.result.projects;
}

function filterProjects(
  projects,
  excludedSkills,
  excludedCountries,
  clientPaymentVerified,
  clientEmailVerified,
  clientDepositMade,
  minimumBudgetFix,
  minimumBudgetHourly
) {
  return projects.filter((project) => {
    const projectCountry = project.location.country.flag_url?.toLowerCase();
    if (
      excludedCountries.some(
        (country) => country.toLowerCase() === projectCountry
      )
    ) {
      return false; // Exclude project
    }

    if (
      project.jobs.some((job) =>
        excludedSkills.includes(job.name.toLowerCase())
      )
    ) {
      return false; // Exclude project
    }

    if (clientPaymentVerified === "yes" && !project.status.payment_verified) {
      return false; // Exclude project
    }

    if (clientEmailVerified === "yes" && !project.status.email_verified) {
      return false; // Exclude project
    }

    if (clientDepositMade === "yes" && !project.status.deposit_made) {
      return false; // Exclude project
    }

    if (
      project.type === "fixed" &&
      project.budget.minimum <= minimumBudgetFix
    ) {
      return false; // Exclude project
    }

    if (
      project.type === "hourly" &&
      project.budget.minimum <= minimumBudgetHourly
    ) {
      return false; // Exclude project
    }

    return true; // Include project
  });
}

async function makeBid(req, project, accessToken, userId, iteration) {
  const { id: bidderId } = req.session.user;
  const {
    id: projectId,
    minimumBudget,
    maximumBudget,
    description,
    bid_stats: bidStats,
    jobs,
    timezone,
    owner_id,
  } = project;
  const averageBid = bidStats.bid_avg;
  const lowRange = req.session.user.lower_bid_range;
  const highRange = req.session.user.higher_bid_range;
  const lowerValue = averageBid * (lowRange / 100);
  const higherValue = averageBid * (highRange / 100);
  const smallValue = averageBid - lowerValue;
  const largeValue = averageBid + higherValue;
  const randomValue = (
    smallValue +
    Math.random() * (largeValue - smallValue)
  ).toFixed(2);
  const bidMoney = parseFloat(randomValue);

  const bidRequestBody = {
    project_id: parseInt(projectId),
    bidder_id: parseInt(bidderId),
    amount: parseFloat(bidMoney),
    period: 3,
    milestone_percentage: 50,
    description: description,
  };

  const response = await axios.post(
    `https://www.freelancer.com/api/projects/0.1/bids/`,
    bidRequestBody,
    {
      headers: {
        "Content-Type": "application/json",
        "freelancer-oauth-v1": accessToken,
      },
    }
  );

  const responseData = response.data;

  // console.log("Bid Response for iteration ${iteration}:", responseData);

  if (responseData.status !== "error") {
    return await Users.updateOne({ _id: userId }, { $inc: { bidsAllow: -1 } });
  }
}

async function updateBidsAllowed(userId, newBidsAllowed) {
  return await Users.updateOne(
    { _id: userId },
    { $set: { bidsAllow: newBidsAllowed } }
  );
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

router.get("/createJob", sessionChecker, async (req, res) => {
  // const url = "https://www.freelancer-sandbox.com/api/users/0.1/self/jobs/";
  // let id = req.session.user._id;
  // let user = await Users.findOne({ _id: id });
  // // let accessToken = user.access_token;
  // let accessToken = "UnkxqQ39gqRWYAUZWVmspVZiK0UbqY";
  // console.log("accessToken--->",accessToken)
  // const headers = { "freelancer-oauth-v1": accessToken };
  // let userSkills = req.session.user.skills;
  // const userSkillsWithValue = userSkills
  //   .map((skill) => {
  //     const matchedSkill = allSkills.find((s) => s.tag === skill);
  //     return matchedSkill ? { skill, value: matchedSkill.value } : null;
  //   })
  //   .filter(Boolean);
  // const userSkillValues = userSkillsWithValue.map((skill) => skill.value);

  // const params = {
  //   jobs: userSkillValues,
  // };

  // try {
  //   const response = await axios.post(url, {
  //     params: params,
  //     headers: headers,
  //   });
  //   console.log("here is response data from jobs----->", response.data.request_id);
  //   const reqId=response.data.request_id;
  //   req.session.request_id=reqId
  //   res.render("myBids");
  // } catch (error) {
  //   // Handle errors
  //   console.error("Error fetching data:", error);
  //   res.status(500).send("An error occurred while fetching data.");
  // }
  const url = "https://www.freelancer.com/api/users/0.1/self/jobs/";

  // Assuming you have already retrieved the access token, user ID, and user skills
  const id = req.session.user._id;
  const user = await Users.findOne({ _id: id });
  const accessToken = user.access_token;
  const userSkills = req.session.user.skills;

  // Assuming allSkills is available and contains skill values
  const userSkillsWithValue = userSkills
    .map((skill) => {
      const matchedSkill = allSkills.find((s) => s.tag === skill);
      return matchedSkill ? { skill, value: matchedSkill.value } : null;
    })
    .filter(Boolean);

  const userSkillValues = userSkillsWithValue
    .map((skill) => parseInt(skill.value))
    .slice(0, 9); // Limits to the first 20 elements
  // console.log("heree are skills------>", userSkillValues);
  const headers = {
    "Content-Type": "application/json",
    "freelancer-oauth-v1": accessToken,
  };

  fetch(url, {
    method: "POST",
    headers: headers,
    body: JSON.stringify({ "jobs[]": userSkillValues }),
  })
    .then((response) => response.json())
    .then((data) => {
      console.log("Response:", data);
    })
    .catch((error) => {
      console.error("Error:", error);
    });
});
// router.get("/search", sessionChecker, async (req, res) => {
//   const url = "https://freelancer.com/api/projects/0.1/projects/all";

//   let id = req.session.user._id;
//   let user = await Users.findOne({ _id: id });

//   let userAutoBid = user.autoBid ? "ON" : "Off";
//   let accessToken = user.access_token;
//   const excludedSkills = user.excluded_skills;
//   const excludedCountries = user.excluded_countries;
//   let userSkills = req.session.user.skills;

//   let userTimezone = req.session.user.timezone.timezone;
//   let userCurrencySign = req.session.user.primary_currency.sign;
//   let userCurrency = req.session.user.primary_currency.name;
//   // console.log("this is user skills---->",req.session.user.skills)
//   // console.log("this is user Timezone---->",req.session.user.timezone.timezone)
//   // console.log("this is user currency sign---->",req.session.user.primary_currency.sign)
//   // console.log("this is user currncy name---->",req.session.user.primary_currency.name)
//   const userSkillsWithValue = userSkills
//     .map((skill) => {
//       const matchedSkill = allSkills.find((s) => s.tag === skill);
//       return matchedSkill ? { skill, value: matchedSkill.value } : null;
//     })
//     .filter(Boolean);
//   const userSkillValues = userSkillsWithValue.map((skill) => Number(skill.value));

//   console.log("here are the value of user skills------>", userSkillValues);

//   const headers = { "freelancer-oauth-v1": accessToken };

//   const page = parseInt(req.query.page, 10) || 1; // Get the page number from the query parameters, default to page 1

//   const pageSize = 5; // Number of items per page

//   const params = {
//     jobs: userSkillValues,
//     min_avg_price: 10,
//     project_statuses: ["active"],
//     full_description: true,
//     job_details: true,
//     user_details: true,
//     location_details: true,
//     user_status: true,
//     user_reputation: true,
//     user_country_details: true,
//     user_display_info: true,
//     user_membership_details: true,
//     user_financial_details: true,

//     compact: true,
//     offset: (page - 1) * pageSize, // Calculate the offset based on the current page
//     limit: pageSize, // Limit the number of items per page
//   };

//   try {
//     const response = await axios.get(url, {
//       params: params,
//       headers: headers,
//     });

//     const responseData = response.data;
//     const projects = responseData.result.projects;
//     console.log("here are projects------>", projects);
//     const numProjects = projects.length;
//     console.log("here are  NO of projects------>", numProjects);
//     const ownerIds = projects.map((project) => project.owner_id);

//     // Initialize an array to store project details
//     let projectsDetails = [];

//     // Loop through ownerIds and make AJAX calls for each owner ID
//     for (let ownerId of ownerIds) {
//       if (!isNaN(ownerId)) {
//         const ownerUrl = `https://freelancer.com/api/users/0.1/users/${ownerId}/`;
//         const ownerResponse = await axios.get(
//           ownerUrl,
//           {
//             jobs: true,
//             reputation: true,
//             employer_reputation: true,
//             reputation_extra: true,
//             employer_reputation_extra: true,
//             job_ranks: true,
//             staff_details: true,
//             completed_user_relevant_job_count: true,
//           },
//           {
//             headers: headers,
//           }
//         );

//         // Push project details to the projectsDetails array
//         console.log("getting user info------", ownerResponse.data.result);
//         projectsDetails.push({
//           username: ownerResponse.data.result.username,
//           publicName: ownerResponse.data.result.public_name,
//           country: ownerResponse.data.result.location.country.name,
//           payment: ownerResponse.data.result.status.payment_verified,
//           email: ownerResponse.data.result.status.email_verified,
//           deposit_made: ownerResponse.data.result.status.deposit_made,
//           identity_verified: ownerResponse.data.result.status.identity_verified,
//           countryShortName: ownerResponse.data.result.timezone.country,
//         });
//       } else {
//         console.log("Invalid owner ID:", ownerId);
//       }
//     }

//     // Flatten the array of arrays into a single array
//     projectsDetails = projectsDetails.flat();

//     // Render projects
//     const projects3 = responseData.result.projects.map((project, index) => ({
//       projectid: project.id,
//       description: project.description,
//       title: project.title,
//       currencyName: project.currency.name,
//       currencySign: project.currency.sign,
//       bidCount: project.bid_stats.bid_count,
//       bidAverage: project.bid_stats.bid_avg,
//       jobNames: project.jobs.map((job) => job.name),
//       minimumBudget: project.budget.minimum,
//       maximumBudget: project.budget.maximum,
//       country: project.location.country.flag_url,
//       fullName: projectsDetails[index].username, // Assuming you want to include the username
//       displayName: projectsDetails[index].publicName, // Include publicName
//       ownerCountry: projectsDetails[index].country, // Include country
//       payment: projectsDetails[index].payment,
//       email: projectsDetails[index].email,
//       deposit_made: projectsDetails[index].deposit_made,
//       identity_verified: projectsDetails[index].identity_verified,
//       countryShortName: projectsDetails[index].countryShortName,
//     }));
//     const projects2 = projects3.filter((project) => {
//       // Convert project's countryShortName to lowercase for case-insensitive comparison
//       const projectCountry = project.countryShortName
//         ? project.countryShortName.toLowerCase()
//         : "";

//       // Check if project's countryShortName matches any excluded country (case-insensitive)
//       if (
//         excludedCountries.some(
//           (country) => country.toLowerCase() === projectCountry
//         )
//       ) {
//         return false; // Exclude project
//       }

//       // Check if project's jobNames include any excluded skill (case-insensitive)
//       if (
//         project.jobNames.some((skill) =>
//           excludedSkills.includes(skill.toLowerCase())
//         )
//       ) {
//         return false; // Exclude project
//       }

//       return true; // Include project
//     });

//     const totalCount = responseData.result.total_count;
//     const totalPages = Math.ceil(totalCount / pageSize);
//     projects2.forEach(project => {
//       let averageBid = parseInt(project.bidAverage);
//       let lowRange = parseInt(user.lower_bid_range);
//       let highRange = parseInt(user.higher_bid_range);

//       const lowerValue = averageBid * (lowRange / 100);
//       const higherValue = averageBid * (highRange / 100);

//       let smallValue = averageBid - lowerValue;
//       let largeValue = averageBid + higherValue;

//       let randomValue = parseFloat((smallValue + Math.random() * (largeValue - smallValue)).toFixed(2));

//       // Add the randomValue to the project object
//       project.randomValue = randomValue;
//     });
//     console.log("here is project 2 Data-------------->", projects2);
//     console.log("userSkills: ",userSkills)
//     console.log("userSkills with values : ",userSkillValues)
//     console.log("here is user : ",user)
//     console.log("here is user id from session : ",id)
//     res.render("searchCopy", {userAutoBid,user,
//       data: projects2,
//       currentPage: page,
//       totalPages: totalPages,
//     });
//   } catch (error) {
//     console.error("Error fetching data:", error);
//     res.status(500).send("Error fetching data");
//   }
// });

let lastFetchedProjectId = null; // To store the ID of the last fetched project

const fetchWithRetry = async (url, options, retries = 3, delay = 1000) => {
  try {
    const response = await axios.get(url, options);
    return response;
  } catch (error) {
    if (retries > 0 && error.response?.status === 429) {
      // Too Many Requests
      console.warn("Rate limit exceeded. Retrying...");
      await new Promise((resolve) => setTimeout(resolve, delay));
      return fetchWithRetry(url, options, retries - 1, delay * 2);
    }
    throw error;
  }
};

router.get("/search", sessionChecker, async (req, res) => {
  const url = "https://freelancer.com/api/projects/0.1/projects/all";

  try {
    let id = req.session.user._id;
    let user = await Users.findOne({ _id: id });

    if (!user) {
      return res.status(404).send("User not found");
    }

    let userAutoBid = user.autoBid ? "ON" : "OFF";
    let accessToken = user.access_token;
    const excludedSkills = user.excluded_skills.map((skill) =>
      skill.toLowerCase()
    );
    const excludedCountries = user.excluded_countries.map((country) =>
      country.toLowerCase()
    );
    let userSkills = req.session.user.skills;

    let userTimezone = req.session.user.timezone.timezone;
    let userCurrencySign = req.session.user.primary_currency.sign;
    let userCurrency = req.session.user.primary_currency.name;

    const userSkillsWithValue = userSkills
      .map((skill) => {
        const matchedSkill = allSkills.find((s) => s.tag === skill);
        return matchedSkill ? { skill, value: matchedSkill.value } : null;
      })
      .filter(Boolean);
    const userSkillValues = userSkillsWithValue.map((skill) =>
      Number(skill.value)
    );

    const headers = { 'content-type': 'application/json',"freelancer-oauth-v1": accessToken };

    const page = parseInt(req.query.page, 10) || 1;
    const pageSize = 5;

    const params = {
      jobs: userSkillValues,
      min_avg_price: 10,
      project_statuses: ["active"],
      full_description: true,
      job_details: true,
      user_details: true,
      location_details: true,
      user_status: true,
      user_reputation: true,
      user_country_details: true,
      user_display_info: true,
      user_membership_details: true,
      user_financial_details: true,
      compact: true,
      offset: (page - 1) * pageSize,
      limit: pageSize,
    };

    // Fetch projects
    const response = await fetchWithRetry(url, { params, headers });
    const responseData = response.data;
    const projects = responseData.result.projects;

    const ownerIds = projects.map((project) => project.owner_id);

    // Fetch project details
    let projectsDetails = await Promise.all(
      ownerIds.map(async (ownerId) => {
        if (!isNaN(ownerId)) {
          const ownerUrl = `https://freelancer.com/api/users/0.1/users/${ownerId}/`;
          try {
            const ownerResponse = await fetchWithRetry(ownerUrl, {
              params: {
                jobs: true,
                reputation: true,
                employer_reputation: true,
                reputation_extra: true,
                employer_reputation_extra: true,
                user_recommendations: true,
                portfolio_details: true,
                preferred_details: true,
                badge_details: true,
                status: true,
              },
              headers,
            });
            const result = ownerResponse.data.result;
            return {
              username: result.username,
              publicName: result.public_name,
              country: result.location.country.name,
              payment: result.status.payment_verified,
              email: result.status.email_verified,
              deposit_made: result.status.deposit_made,
              identity_verified: result.status.identity_verified,
              countryShortName: result.timezone.country,
              userReviews:
                result?.employer_reputation.entire_history.reviews ?? 0,
              userLastThree: result?.employer_reputation.last3months.all ?? 0,
              userLastTwelve: result?.employer_reputation.last12months.all ?? 0,
              userTotalProjects:
                result?.employer_reputation.entire_history.all ?? 0,
              userRating:
                result?.employer_reputation.entire_history.overall ?? 0,
            };
          } catch (error) {
            console.error(
              "Error fetching owner details for ID:",
              ownerId,
              error
            );
            return null;
          }
        } else {
          console.log("Invalid owner ID:", ownerId);
          return null;
        }
      })
    );

    projectsDetails = projectsDetails.filter(Boolean);

    const projects3 = responseData.result.projects.map((project, index) => ({
      projectid: project.id,
      description: project.description,
      title: project.title,
      currencyName: project.currency.name,
      currencySign: project.currency.sign,
      bidCount: project.bid_stats.bid_count,
      bidAverage: project.bid_stats.bid_avg,
      jobNames: project.jobs.map((job) => job.name),
      minimumBudget: project.budget.minimum,
      maximumBudget: project.budget.maximum,
      country: project.location.country.flag_url,
      fullName: projectsDetails[index]?.username || "",
      displayName: projectsDetails[index]?.publicName || "",
      ownerCountry: projectsDetails[index]?.country || "",
      payment: projectsDetails[index]?.payment || false,
      email: projectsDetails[index]?.email || false,
      deposit_made: projectsDetails[index]?.deposit_made || false,
      identity_verified: projectsDetails[index]?.identity_verified || false,
      countryShortName: projectsDetails[index]?.countryShortName || "",
      reviews: projectsDetails[index]?.userReviews || 0,
      allProjects: projectsDetails[index]?.userTotalProjects || 0,
      yearlyProject: projectsDetails[index]?.userLastTwelve || 0,
      quaterlyProject: projectsDetails[index]?.userLastThree || 0,
      rating: projectsDetails[index]?.userRating || 0,
    }));

    const projects2 = projects3.filter((project) => {
      const projectCountry = project.countryShortName
        ? project.countryShortName.toLowerCase()
        : "";
      if (excludedCountries.includes(projectCountry)) {
        return false;
      }
      if (
        project.jobNames.some((skill) =>
          excludedSkills.includes(skill.toLowerCase())
        )
      ) {
        return false;
      }
      return true;
    });

    const totalCount = responseData.result.total_count;
    const totalPages = Math.ceil(totalCount / pageSize);

    projects2.forEach((project) => {
      let averageBid = parseInt(project.bidAverage);
      let lowRange = parseInt(user.lower_bid_range);
      let highRange = parseInt(user.higher_bid_range);

      const lowerValue = averageBid * (lowRange / 100);
      const higherValue = averageBid * (highRange / 100);

      let smallValue = averageBid - lowerValue;
      let largeValue = averageBid + higherValue;

      let randomValue = Math.floor(
        smallValue + Math.random() * (largeValue - smallValue)
      );
      project.randomValue = randomValue;
    });

    res.render("searchCopy", {
      userAutoBid,
      user,
      data: projects2,
      currentPage: page,
      totalPages: totalPages,
      projectIds: projects2.map((project) => project.projectid),
    });
  } catch (error) {
    if (error.response) {
      console.error("Error fetching data: ", error.response.data);
      console.error("Status code: ", error.response.status);
      if (!error.response.data.message) {
        return res
          .status(500)
          .send(`Error fetching data: ${error.message || "Unknown error"}`);
      } else {
        return res
          .status(500)
          .send(
            `Error fetching data: ${
              error.response.data.message || "Unknown error"
            }`
          );
      }
    } else if (error.request) {
      console.error("No response received from API: ", error.request);
      return res.status(500).send("No response from API server.");
    } else {
      console.error("Error setting up request: ", error.message);
      return res.status(500).send("Request setup error: " + error.message);
    }
  }
});
// To store the ID of the last fetched project

router.get("/checkNewProjects", sessionChecker, async (req, res) => {
  const url = "https://freelancer.com/api/projects/0.1/projects/all";

  try {
    let id = req.session.user._id;
    let user = await Users.findOne({ _id: id });

    if (!user) {
      return res.status(404).send("User not found");
    }

    let accessToken = user.access_token;
    const excludedSkills = user.excluded_skills.map((skill) =>
      skill.toLowerCase()
    );
    const excludedCountries = user.excluded_countries.map((country) =>
      country.toLowerCase()
    );
    let userSkills = req.session.user.skills;

    const userSkillsWithValue = userSkills
      .map((skill) => {
        const matchedSkill = allSkills.find((s) => s.tag === skill);
        return matchedSkill ? { skill, value: matchedSkill.value } : null;
      })
      .filter(Boolean);
    const userSkillValues = userSkillsWithValue.map((skill) =>
      Number(skill.value)
    );

    const headers = { 'content-type': 'application/json',"freelancer-oauth-v1": accessToken };

    const params = {
      jobs: userSkillValues,
      min_avg_price: 10,
      project_statuses: ["active"],
      full_description: true,
      compact: true,
      limit: 1, // Only fetch the most recent project
    };

    // Fetch the most recent project using fetchWithRetry
    const response = await fetchWithRetry(url, {
      params: params,
      headers: headers,
    });

    const responseData = response.data;
    const projects = responseData.result.projects;

    if (projects.length > 0) {
      const latestProjectId = projects[0].id;

      if (lastFetchedProjectId && latestProjectId !== lastFetchedProjectId) {
        lastFetchedProjectId = latestProjectId;
        return res.json({ newProject: true, project: projects[0] });
      }

      lastFetchedProjectId = latestProjectId;
    }

    res.json({ newProject: false });
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).send("Error fetching data");
  }
});

router.post("/place/automaticBid", sessionChecker, async (req, res) => {
  try {
    const {
      bid_price,
      project_id,
      project_title,
      user_name,
      project_jobs,
      project_country,
    } = req.body;

    const title = project_title;
    const username = user_name;
    const jobNames = project_jobs.split(",");
    const country = project_country;

    const userId = req.session.user._id;
    const user = await Users.findById(userId);
    if (!user) {
      console.error("User not found:", userId);
      return res.status(404).send("User not found.");
    }

    const projId = parseInt(project_id);
    const amount = parseFloat(bid_price);
    let accessToken = user.access_token;

    const refreshToken = user.refresh_token;
    const tokenExpirationDate = new Date(user.tokenExpirationDate);
    const currentTime = new Date();

    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;

    // Check if the access token is expired or about to expire
    if (currentTime >= tokenExpirationDate) {
      const tokenResponse = await axios.post(
        "https://www.freelancer.com/api/oauth/refresh",
        {
          refresh_token: refreshToken,
          grant_type: "refresh_token",
          client_id: clientId,
          client_secret: clientSecret,
        }
      );

      if (tokenResponse.data?.access_token) {
        accessToken = tokenResponse.data.access_token;
        const newExpirationDate = new Date();
        newExpirationDate.setSeconds(
          newExpirationDate.getSeconds() + tokenResponse.data.expires_in
        );

        await Users.updateOne(
          { _id: userId },
          {
            $set: {
              access_token: accessToken,
              tokenExpirationDate: newExpirationDate,
            },
          }
        );
      } else {
        return res.status(500).send("Failed to refresh access token.");
      }
    }

    const userSkills = user.skills;
    const templates = await Templates.find({ userId }).populate("category");
    console.log("Templates for user:", templates);
    if (!templates.length)
      return res.status(404).send("No templates found for the user.");

    const randomlyInclude = (probability) => Math.random() < probability;

    const filteredTemplates = templates.filter((template) => {
      const alwaysInclude = template.category?.always_include;
      return alwaysInclude || randomlyInclude(0.5);
    });

    const groupedAndSortedTemplates = filteredTemplates.reduce(
      (acc, template) => {
        const categoryId = template.category?._id.toString();
        if (!acc[categoryId]) {
          acc[categoryId] = {
            position: template.category.position,
            templates: [],
          };
        }
        acc[categoryId].templates.push(template);
        return acc;
      },
      {}
    );

    const sortedCategories = Object.values(groupedAndSortedTemplates).sort(
      (a, b) => a.position - b.position
    );

    const getFinalContentForProject = (title, username, categories, skills) => {
      return categories.reduce((acc, category) => {
        const randomTemplateIndex = Math.floor(
          Math.random() * category.templates.length
        );
        const selectedTemplate = category.templates[randomTemplateIndex];
        const matchingSkills = jobNames.filter((jobName) =>
          skills.includes(jobName)
        );

        const replacedContent = selectedTemplate.content
          .replace(/{{Project Title}}/g, title)
          .replace(/{{Owner Name}}/g, username)
          .replace(/{{Owner Full Name}}/g, username)
          .replace(/{{Job Skills}}/g, skills.slice(0, 5).join(", "))
          .replace(/{{Matching Job Skills}}/g, matchingSkills.join(", "))
          .replace(/{{Owner First Name}}/g, username.split(" ")[0] || username)
          .replace(/{{Country}}/g, country)
          .replace(/{{NewLine}}/g, "\n");

        return acc + replacedContent + "\n";
      }, "");
    };

    const finalContent = getFinalContentForProject(
      title,
      username,
      sortedCategories,
      userSkills
    );
    console.log("API Request Data:", {
      project_id: projId,
      bidder_id: parseInt(user.id),
      amount: amount,
      description: finalContent,
    });
    console.log(accessToken);

    const responseData = await axios.post(
      `https://www.freelancer.com/api/projects/0.1/bids/?compact=`,
      {
        project_id: projId,
        bidder_id: parseInt(user.id),
        amount: amount,
        period: 7,
        milestone_percentage: 50,
        description: finalContent,
      },
      {
        headers: {
          "content-type": "application/json",
          "freelancer-oauth-v1": accessToken,
        },
      }
    );

    console.log("API Response Data:", responseData.data);
    if (responseData.data.status !== "error") {
      const updatedBidsAllowed = Math.max(user.bidsAllow - 1, 0);
      await Users.updateOne(
        { _id: userId },
        { $set: { bidsAllow: updatedBidsAllowed } }
      );

      await Projects.create({
        bidDescription: finalContent,
        projectTitle: title,
        bidAmount: responseData.data.result.amount,
        userName: username,
        time: new Date().toISOString().split("T")[0],
        user: userId,
      });
    }

    return res.status(200).json(finalContent);
  } catch (error) {
    console.error("Error details:", {
      message: error.message,
      stack: error.stack,
      response: error.response?.data,
    });

    if (error.response) {
      return res.status(500).send(`API Error: ${error.response.data.message}`);
    } else if (error.request) {
      return res.status(500).send("No response from API server.");
    } else {
      return res.status(500).send(`Internal Server Error: ${error.message}`);
    }
  }
});

router.get("/bidai", sessionChecker, async (req, res) => {
  const pricing = await Payments.find({});
  res.render("bidmanAi", { pricing });
});

router.get("/autobid", sessionChecker, (req, res) => {
  res.render("autobid");
});

router.get("/add_skill_set", sessionChecker, async (req, res) => {
  res.render("add-skills");
});
router.post("/placeBid", sessionChecker, async (req, res) => {
  try {
    // Extract data from the request body
    const { customizeData, bidPrice, project_id } = req.body;
    // console.log("req body yayayyaay--->", req.body);
    // Retrieve user data
    const id = req.session.user._id; // Update with the correct user ID retrieval mechanism
    let title = req.body.title;
    let username = req.body.user_name;
    const user = await Users.findOne({ _id: id });
    const userId = parseInt(user.id);
    // console.log("here is userId-------->", userId);
    // let request_Id = req.session.request_id;
    // console.log("here is requestId-------->", request_Id);
    let projId = parseInt(project_id);
    let amount = parseFloat(bidPrice);
    let accessToken = user.access_token;
    // let accessToken = '2a0e0fde884b8f422172da1a91771b6c';
    // console.log("here is access Token-------->", accessToken);
    const versionNumber = 0.1;

    // Make the POST request to Freelancer API using fetch
    const response = await fetch(
      `https://www.freelancer.com/api/projects/0.1/bids/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "freelancer-oauth-v1": accessToken,
        },
        body: JSON.stringify({
          project_id: projId,
          bidder_id: Number(userId),
          amount: amount,
          period: 3,
          milestone_percentage: 50,
          description: customizeData,
          // profile_id: userId,
        }),
      }
    );

    // Parse the JSON response
    const responseData = await response.json();
    if (responseData.status !== "error") {
      let id = req.session.user._id;
      let user = await Users.findOne({ _id: id });
      let bidsAllowed = user.bidsAllow - 1;
      if (bidsAllowed < 0) {
        bidsAllowed = 0; // Ensure bidsAllowed doesn't go below 0
      }
      await Users.updateOne({ _id: id }, { $set: { bidsAllow: bidsAllowed } });
      let dateString = responseData.result.submitdate;
      const date = new Date().toISOString().split("T")[0];
      const newRecord = await Projects.create({
        // Define the fields of the new record
        bidDescription: customizeData,
        projectTitle: title,
        bidAmount: responseData.result.amount,
        userName: username,
        time: date,
        user: req.session.user._id,
        // Add more fields as needed
      });
    }
    // Log response and send data back to client
    // console.log("Response:", responseData);
    return res.status(200).json(responseData);
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/generate/randomBid", sessionChecker, async (req, res) => {
  try {
    // console.log("here is data---->", req.body);
    let userId = req.session.user._id;
    // console.log("user id---->", userId);

    // Fetch templates and user details
    const templates = await Templates.find({ userId: userId }).populate(
      "category"
    );
    const user = await Users.find({ _id: userId });

    // console.log("here are templates------>", templates);
    // console.log("here are user------>", user[0].skills);
    // console.log("here are job------>", req.body.jobName);

    // Split jobName into an array of jobSkills
    const jobSkills = req.body.jobName.split(",");
    const userSkills = user[0].skills;

    // Function to randomly decide inclusion for templates with always_include = false
    const randomlyInclude = (probability) => Math.random() < probability;

    // Filter templates by category, deciding randomly for always_include = false
    const filteredTemplates = templates.filter((template) => {
      if (template.category && template.category.always_include === true) {
        return true; // Always include
      } else if (
        template.category &&
        template.category.always_include === false
      ) {
        return randomlyInclude(0.5); // 50% chance to include
      }
      return false; // Exclude if category is not defined or always_include is not specified
    });

    // Group and sort filteredTemplates by category position
    const groupedAndSortedTemplates = filteredTemplates.reduce(
      (acc, template) => {
        const categoryId = template.category._id.toString();
        if (!acc[categoryId]) {
          acc[categoryId] = {
            position: template.category.position,
            templates: [],
          };
        }
        acc[categoryId].templates.push(template);
        return acc;
      },
      {}
    );

    // Convert object to array and sort by position
    const sortedCategories = Object.values(groupedAndSortedTemplates).sort(
      (a, b) => a.position - b.position
    );
    // console.log(sortedCategories);

    // Selecting one random template from each category and building the final content string
    let finalContent = sortedCategories.reduce((acc, category) => {
      const randomTemplateIndex = Math.floor(
        Math.random() * category.templates.length
      );
      const selectedTemplate = category.templates[randomTemplateIndex];

      // Replace placeholders in selectedTemplate.content with actual values
      const matchingSkills = jobSkills
        .filter((jobName) => userSkills.includes(jobName))
        .join(", ");
      const replacedContent = selectedTemplate.content
        .replace(/{{Project Title}}/g, req.body.title)
        .replace(/{{Owner Name}}/g, req.body.user_name)
        .replace(/{{Owner Full Name}}/g, req.body.user_name)
        .replace(/{{Matching Job Skills}}/g, matchingSkills)
        .replace(/{{Job Skills}}/g, user[0].skills.slice(0, 5).join(", "))
        .replace(
          /{{Owner First Name}}/g,
          req.body.user_name.split(" ")[0] || req.body.user_name
        )
        .replace(/{{Country}}/g, req.body.country)
        .replace(/{{NewLine}}/g, "\n"); // Replace {{NewLine}} with actual newline character

      return acc + replacedContent + "\n"; // Ensure each template content ends with a newline
    }, "");

    let contentToSend = finalContent;
    // console.log("here is content----------", contentToSend);
    return res.status(200).send(contentToSend);
  } catch (error) {
    console.error("Error generating random bid:", error);
    // Handle the error and send an appropriate response
    res.status(500).send("ERROR");
  }
});
router.get("/positions", sessionChecker, async (req, res) => {
  try {
    // Fetch existing positions from the TemplateCategories collection
    const existingPositions = await TemplateCategories.find(
      {},
      "position"
    ).sort({ position: 1 });

    let positionsArray = [];

    // Extract position values from existing records
    positionsArray = existingPositions.map((position) => position.position);

    // Generate suggestions excluding positions that are already taken
    let suggestions = [];
    for (let i = 1; i <= 100; i++) {
      if (!positionsArray.includes(i)) {
        suggestions.push(i);
      }
    }

    // Take only the first 5 available positions
    const availablePositions = suggestions.slice(0, 5);

    res.status(200).json(availablePositions);
  } catch (error) {
    console.error("Error fetching existing positions:", error);
    res.status(500).send("Internal Server Error");
  }
});

router.get("/skill-sets/delete/:id", sessionChecker, async (req, res) => {
  await SkillSets.findByIdAndDelete(req.params.id);
  res.redirect("/skills-sets");
});
router.get("/payment", sessionChecker, async (req, res) => {
  res.render("subscription");
});

router.post("/countries", sessionChecker, async (req, res) => {
  try {
    // console.log("Here in country submission body--->", req.body);

    const userId = req.session.user._id;
    // console.log("Here in country submission body userId--->", userId);

    // Update the user's excluded countries
    const result = await Users.findOneAndUpdate(
      { _id: userId },
      { excluded_countries: req.body.countries },
      { new: true } // Return the updated document
    );

    if (!result) {
      console.error("User not found or update failed");
      return res.redirect("/countries?error=updateFailed");
    }

    // console.log("User excluded countries:", result.excluded_countries);

    // Redirect with success message
    res.redirect("/countries?success=true");
  } catch (error) {
    console.error("Error updating excluded countries:", error);
    res.redirect("/countries?error=unknown");
  }
});

router.post("/skill_set_add", sessionChecker, async (req, res) => {
  let skillIds = req.body.skills.split(",");
  // console.log(skillIds);
  // console.log("this is session------>", req.session.user);
  userId = req.session.user._id;
  // Find skill names corresponding to the IDs
  let skillNames = allSkills
    .filter((skill) => skillIds.includes(skill.value))
    .map((skill) => skill.tag);

  // console.log(skillNames);

  // Do something with the skillNames, like saving them or processing further

  let skillSet = new SkillSets({
    name: req.body.name,
    skills: skillNames,
    user: userId,
  });

  await skillSet.save();

  res.redirect("/skills-sets");
});

router.post("/exculded_skills", sessionChecker, async (req, res) => {
  try {
    // console.log(req.body); // Log the incoming request body for debugging

    // Retrieve the user ID from the session
    const userId = req.session?.user?._id;
    if (!userId) {
      return res.status(400).send("User not logged in.");
    }

    // Find the user in the database
    const user = await Users.findById(userId);
    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Handle 'show_excluded_skills' checkbox value
    user.show_excluded_skills = req.body.show_excluded_skills === "on"; // Convert "on" to true and undefined to false

    // Handle 'excluded_skills' as an array
    user.excluded_skills = Array.isArray(req.body.skills)
      ? req.body.skills
      : [req.body.skills].filter(Boolean); // Ensure array and remove falsy values

    // Save the user document
    await user.save();

    // Redirect with a success message
    res.redirect("/skills?message=Excluded skills saved successfully.");
  } catch (error) {
    console.error("Error saving excluded skills:", error);
    res.status(500).send("An error occurred while saving excluded skills.");
  }
});

router.post("/saveSkillsPriority", sessionChecker, async (req, res) => {
  let skillOrder = req.body;
  // console.log("Received skill order:", skillOrder);
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let hide = user.hide_skills;
  // console.log("Received skill order2: ", hide);
  skillOrder = [...skillOrder, ...hide];
  // console.log("Received skill order3: ", skillOrder);
  await Users.findOneAndUpdate(
    { _id: userId },
    { $set: { skills: skillOrder } }, // Using $set to update the skills field
    { new: true } // Return the updated document
  );
  // Here, you would typically save the skill order to a database
  // After saving, respond back with success message or the saved order
  res.status(200).json(skillOrder);
});

router.post("/skills", async (req, res) => {
  try {
    const skills = req.body.skills || []; // Default to an empty array
    const userId = req.session?.user?._id; // Use optional chaining to avoid errors
    if (!userId) {
      res.redirect("/login");
    }

    let user = await Users.findById(userId);
    if (!user) {
      res.redirect("/login");
    }

    let userSkills = user.skills || []; // Default to an empty array
    // console.log(skills, "here is dimaria");
    // console.log(userSkills, "here is messi");

    // Determine missing skills
    const missingInSkills = userSkills.filter(
      (skill) => !skills.includes(skill)
    );
    const missingInUserSkills = skills.filter(
      (skill) => !userSkills.includes(skill)
    );

    // Update user data
    user.hide_skills = missingInSkills;

    await user.save();

    // Redirect back to /skills
    res.redirect("/skills");
  } catch (error) {
    console.error("Error in /skills route:", error);
    res.status(500).send("An error occurred while processing skills.");
  }
});

router.get("/skills", sessionChecker, async (req, res) => {
  const userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  const currentUrl = req.originalUrl || "/skills";
  // console.log(user);
  // console.log(user)
  //   let access_token = user.access_token

  //   const url = "https://freelancer-sandbox.com/api/users/0.1/users/"+user.id;

  //   const headers = {'freelancer-oauth-v1': access_token};

  //   // // Data payload as JSON, here you need to properly set ids, user_id, and seo_url as necessary
  //   //   const data = {
  //   //   // ids: [Number(user.id)],             // This should be the array of IDs you're interested in
  //   //   user_id: Number(user.id),           // The user ID for the request
  //   //   seo_url: user.username // Optional SEO URL parameter
  //   //   };
  //   let response = await axios.get(url, { headers,})

  //   if(response.data){
  // console.log(response.data)
  //   }else{
  //     console.log(error)
  //   }
  if (!req.originalUrl || req.originalUrl === "") {
    req.originalUrl = "/skills";
  }

  res.render("skills", {
    currentUrl: currentUrl,
    userAutoBid,
    hideSkills: user.hide_skills,
    skills: user.skills || [],
    excluded_skills:
      user.excluded_skills.map((skill) => skill.replace(/\//g, "/")) || [], // Escape forward slashes
    show_excluded_skills: user.show_excluded_skills || false,
  });
});

router.get("/skills-sets", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/skills-sets";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  let skillsets = await SkillSets.find({ user: userId });
  res.render("skills-sets", {
    currentUrl: currentUrl,
    userAutoBid,
    skillsets: skillsets || [],
  });
});

router.get("/countries", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/countries";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let excluded = user.excluded_countries;
  // console.log("here is excluded countries lise", user.excluded_countries);
  let userAutoBid = user.autoBid ? "ON" : "Off";

  res.render("countries", {
    currentUrl: currentUrl,
    userAutoBid,
    excluded_countries: user.excluded_countries,
  });
});

router.get("/client-stats", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/client-stats";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  res.render("clientStats", {
    currentUrl: currentUrl,
    userAutoBid,
    payment_verified: user.payment_verified,
    email_verified: user.email_verified,
    deposit_made: user.deposit_made,
    rating: user.rating,
    projects: user.projects,
  });
});

router.post("/client_stats", sessionChecker, async (req, res) => {
  // console.log(req.body);
  let userId = req.session.user._id;
  await Users.findOneAndUpdate(
    { _id: userId },
    {
      payment_verified: req.body.payment_verified,
      email_verified: req.body.email_verified,
      deposit_made: req.body.deposit_made,
      rating: req.body.rating,
      projects: req.body.projects,
    }
  );
  res.redirect("/client-stats");
});

router.get("/budget", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/budget";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  res.render("budget", {
    currentUrl: currentUrl,
    userAutoBid,
    minimum_budget_fixed: user?.minimum_budget_fixed,
    minimum_budget_hourly: user?.minimum_budget_hourly,
  });
});

router.post("/budget", sessionChecker, async (req, res) => {
  let userId = req.session.user._id;
  await Users.findOneAndUpdate(
    { _id: userId },
    {
      minimum_budget_fixed: req.body.minimum_budget_fixed,
      minimum_budget_hourly: req.body.minimum_budget_hourly,
    }
  );
  res.redirect("/budget");
});

router.get("/bidPrice", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/bidPrice";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  const biddingPrice = await Biddingprice.findOne({ user: userId });
  let userAutoBid = user.autoBid ? "ON" : "Off";
  // console.log("user bidding : ", biddingPrice);
  res.render("bidPrice", {
    currentUrl: currentUrl,
    userAutoBid,
    higher_bid_range: user.higher_bid_range,
    lower_bid_range: user.lower_bid_range,
    biddingPrice,
  });
});
router.get("/timeSetting", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/timeSetting";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  res.render("timeSetting", {
    currentUrl: currentUrl,
    userAutoBid,
    timeInterval: user.timeInterval,
    timeLimit: user.timeLimit,
    bidsLimit: user.bidsLimit,
  });
});

router.post("/timeSetting", sessionChecker, async (req, res) => {
  try {
    let userId = req.session.user._id;
    // console.log("here is req body", req.body);

    await Users.findOneAndUpdate(
      { _id: userId },
      {
        timeInterval: req.body.time_interval,
        timeLimit: req.body.time_limit,
        bidsLimit: req.body.bid_limit,
      }
    );

    // Redirect with success parameter
    res.redirect("/timeSetting?success=true");
  } catch (error) {
    console.error(error);
    // Handle error (you may want to redirect with an error parameter)
    res.redirect("/timeSetting?success=false");
  }
});
router.post("/bidPrice", sessionChecker, async (req, res) => {
  // console.log("here is data from bid: ", req.body);
  let userId = req.session.user._id;
  await Users.findOneAndUpdate(
    { _id: userId },
    {
      higher_bid_range: req.body.higher_bid_range,
      lower_bid_range: req.body.lower_bid_range,
    }
  );
  const data = req.body;

  // Format data into the schema format
  const formattedData = {
    micro_project: {
      budget: data["micro-project-budget"],
      bid_usd_aud_cad: data["micro-project-usd-aud-cad-10-30"]
        ? parseFloat(data["micro-project-usd-aud-cad-10-30"])
        : undefined,
      bid_gbp: data["micro-project-gbp-10-20"]
        ? parseFloat(data["micro-project-gbp-10-20"])
        : undefined,
      bid_eur: data["micro-project-eur-8-30"]
        ? parseFloat(data["micro-project-eur-8-30"])
        : undefined,
      bid_inr: data["micro-project-inr-600-1500"]
        ? parseFloat(data["micro-project-inr-600-1500"])
        : undefined,
      bid_sgd: data["micro-project-sgd-12-30"]
        ? parseFloat(data["micro-project-sgd-12-30"])
        : undefined,
      bid_nzd: data["micro-project-nzd-14-30"]
        ? parseFloat(data["micro-project-nzd-14-30"])
        : undefined,
      bid_hkd: data["micro-project-hkd-80-240"]
        ? parseFloat(data["micro-project-hkd-80-240"])
        : undefined,
      budget_range_usd_aud_cad: data["micro-project-usd-aud-cad-10-30"]
        ? "10-30"
        : undefined,
      budget_range_gbp: data["micro-project-gbp-10-20"] ? "10-20" : undefined,
      budget_range_eur: data["micro-project-eur-8-30"] ? "8-30" : undefined,
      budget_range_inr: data["micro-project-inr-600-1500"]
        ? "600-1500"
        : undefined,
      budget_range_sgd: data["micro-project-sgd-12-30"] ? "12-30" : undefined,
      budget_range_nzd: data["micro-project-nzd-14-30"] ? "14-30" : undefined,
      budget_range_hkd: data["micro-project-hkd-80-240"] ? "80-240" : undefined,
    },
    simple_project: {
      budget: data["simple-project-budget"],
      bid_usd_eur_aud_cad_nzd_sgd: data[
        "simple-project-usd-eur-aud-cad-nzd-sgd-30-250"
      ]
        ? parseFloat(data["simple-project-usd-eur-aud-cad-nzd-sgd-30-250"])
        : undefined,
      bid_gbp: data["simple-project-gbp-20-250"]
        ? parseFloat(data["simple-project-gbp-20-250"])
        : undefined,
      bid_inr: data["simple-project-inr-1500-12500"]
        ? parseFloat(data["simple-project-inr-1500-12500"])
        : undefined,
      bid_hkd: data["simple-project-hkd-240-2000"]
        ? parseFloat(data["simple-project-hkd-240-2000"])
        : undefined,
      budget_range_usd_eur_aud_cad_nzd_sgd: "30-250",
      budget_range_gbp: "20-250",
      budget_range_inr: "1500-12500",
      budget_range_hkd: "240-2000",
    },
    very_small_project: {
      budget: data["very-small-project-budget"],
      bid_usd_gbp_eur_aud_cad_nzd_sgd: data[
        "very-small-project-usd-gbp-eur-aud-cad-nzd-sgd-250-750"
      ]
        ? parseFloat(
            data["very-small-project-usd-gbp-eur-aud-cad-nzd-sgd-250-750"]
          )
        : undefined,
      bid_inr: data["very-small-project-inr-12500-37500"]
        ? parseFloat(data["very-small-project-inr-12500-37500"])
        : undefined,
      bid_hkd: data["very-small-project-hkd-2000-6000"]
        ? parseFloat(data["very-small-project-hkd-2000-6000"])
        : undefined,
      budget_range_usd_gbp_eur_aud_cad_nzd_sgd: "250-750",
      budget_range_inr: "12500-37500",
      budget_range_hkd: "2000-6000",
    },
    small_project: {
      budget: data["small-project-budget"],
      bid_usd_gbp_eur_aud_cad_nzd_sgd: data[
        "small-project-usd-gbp-eur-aud-cad-nzd-sgd-750-1500"
      ]
        ? parseFloat(data["small-project-usd-gbp-eur-aud-cad-nzd-sgd-750-1500"])
        : undefined,
      bid_inr: data["small-project-inr-37500-75000"]
        ? parseFloat(data["small-project-inr-37500-75000"])
        : undefined,
      bid_hkd: data["small-project-hkd-6000-12000"]
        ? parseFloat(data["small-project-hkd-6000-12000"])
        : undefined,
      budget_range_usd_gbp_eur_aud_cad_nzd_sgd: "750-1500",
      budget_range_inr: "37500-75000",
      budget_range_hkd: "6000-12000",
    },
    medium_project: {
      budget: data["medium-project-budget"],
      bid_usd_gbp_eur_aud_cad_nzd_sgd: data[
        "medium-project-usd-gbp-eur-aud-cad-nzd-sgd-1500-3000"
      ]
        ? parseFloat(
            data["medium-project-usd-gbp-eur-aud-cad-nzd-sgd-1500-3000"]
          )
        : undefined,
      bid_inr: data["medium-project-inr-75000-150000"]
        ? parseFloat(data["medium-project-inr-75000-150000"])
        : undefined,
      bid_hkd: data["medium-project-hkd-12000-24000"]
        ? parseFloat(data["medium-project-hkd-12000-24000"])
        : undefined,
      budget_range_usd_gbp_eur_aud_cad_nzd_sgd: "1500-3000",
      budget_range_inr: "75000-150000",
      budget_range_hkd: "12000-24000",
    },
    large_project: {
      budget: data["large-project-budget"],
      bid_usd_gbp_eur_aud_cad_nzd_sgd: data[
        "large-project-usd-gbp-eur-aud-cad-nzd-sgd-3000-5000"
      ]
        ? parseFloat(
            data["large-project-usd-gbp-eur-aud-cad-nzd-sgd-3000-5000"]
          )
        : undefined,
      bid_inr: data["large-project-inr-150000-250000"]
        ? parseFloat(data["large-project-inr-150000-250000"])
        : undefined,
      bid_hkd: data["large-project-hkd-24000-40000"]
        ? parseFloat(data["large-project-hkd-24000-40000"])
        : undefined,
      budget_range_usd_gbp_eur_aud_cad_nzd_sgd: "3000-5000",
      budget_range_inr: "150000-250000",
      budget_range_hkd: "24000-40000",
    },
    basic_hourly: {
      rate: data["basic-hourly-rate"],
      bid_usd_aud_cad: data["basic-hourly-usd-aud-cad-2-8"]
        ? parseFloat(data["basic-hourly-usd-aud-cad-2-8"])
        : undefined,
      bid_gbp: data["basic-hourly-gbp-2-5"]
        ? parseFloat(data["basic-hourly-gbp-2-5"])
        : undefined,
      bid_eur: data["basic-hourly-eur-2-6"]
        ? parseFloat(data["basic-hourly-eur-2-6"])
        : undefined,
      bid_inr: data["basic-hourly-inr-100-400"]
        ? parseFloat(data["basic-hourly-inr-100-400"])
        : undefined,
      bid_nzd_sgd: data["basic-hourly-nzd-sgd-3-10"]
        ? parseFloat(data["basic-hourly-nzd-sgd-3-10"])
        : undefined,
      bid_hkd: data["basic-hourly-hkd-16-65"]
        ? parseFloat(data["basic-hourly-hkd-16-65"])
        : undefined,
      budget_range_usd_aud_cad: "2-8",
      budget_range_gbp: "2-5",
      budget_range_eur: "2-6",
      budget_range_inr: "100-400",
      budget_range_nzd_sgd: "3-10",
      budget_range_hkd: "16-65",
    },
    moderate_hourly: {
      rate: data["moderate-hourly-rate"],
      bid_usd_aud_cad: data["moderate-hourly-usd-aud-cad-8-15"]
        ? parseFloat(data["moderate-hourly-usd-aud-cad-8-15"])
        : undefined,
      bid_gbp: data["moderate-hourly-gbp-5-10"]
        ? parseFloat(data["moderate-hourly-gbp-5-10"])
        : undefined,
      bid_eur: data["moderate-hourly-eur-6-12"]
        ? parseFloat(data["moderate-hourly-eur-6-12"])
        : undefined,
      bid_inr: data["moderate-hourly-inr-400-750"]
        ? parseFloat(data["moderate-hourly-inr-400-750"])
        : undefined,
      bid_nzd_sgd: data["moderate-hourly-nzd-sgd-10-20"]
        ? parseFloat(data["moderate-hourly-nzd-sgd-10-20"])
        : undefined,
      bid_hkd: data["moderate-hourly-hkd-65-115"]
        ? parseFloat(data["moderate-hourly-hkd-65-115"])
        : undefined,
      budget_range_usd_aud_cad: "8-15",
      budget_range_gbp: "5-10",
      budget_range_eur: "6-12",
      budget_range_inr: "400-750",
      budget_range_nzd_sgd: "10-20",
      budget_range_hkd: "65-115",
    },
    standard_hourly: {
      rate: data["standard-hourly-rate"],
      bid_usd_aud_cad: data["standard-hourly-usd-aud-cad-15-25"]
        ? parseFloat(data["standard-hourly-usd-aud-cad-15-25"])
        : undefined,
      bid_gbp: data["standard-hourly-gbp-10-15"]
        ? parseFloat(data["standard-hourly-gbp-10-15"])
        : undefined,
      bid_eur: data["standard-hourly-eur-6-12"]
        ? parseFloat(data["standard-hourly-eur-6-12"])
        : undefined,
      bid_inr: data["standard-hourly-inr-750-1250"]
        ? parseFloat(data["standard-hourly-inr-750-1250"])
        : undefined,
      bid_nzd_sgd: data["standard-hourly-nzd-sgd-20-30"]
        ? parseFloat(data["standard-hourly-nzd-sgd-20-30"])
        : undefined,
      bid_hkd: data["standard-hourly-hkd-115-200"]
        ? parseFloat(data["standard-hourly-hkd-115-200"])
        : undefined,
      budget_range_usd_aud_cad: "15-25",
      budget_range_gbp: "10-20",
      budget_range_eur: "6-12",
      budget_range_inr: "750-1250",
      budget_range_nzd_sgd: "20-30",
      budget_range_hkd: "115-200",
    },
    skilled_hourly: {
      rate: data["skilled-hourly-rate"],
      bid_usd_aud_cad: data["skilled-hourly-usd-aud-cad-25-50"]
        ? parseFloat(data["skilled-hourly-usd-aud-cad-25-50"])
        : undefined,
      bid_gbp: data["skilled-hourly-gbp-18-36"]
        ? parseFloat(data["skilled-hourly-gbp-18-36"])
        : undefined,
      bid_eur: data["skilled-hourly-eur-18-36"]
        ? parseFloat(data["skilled-hourly-eur-18-36"])
        : undefined,
      bid_inr: data["skilled-hourly-inr-1250-2500"]
        ? parseFloat(data["skilled-hourly-inr-1250-2500"])
        : undefined,
      bid_nzd_sgd: data["skilled-hourly-nzd-sgd-30-60"]
        ? parseFloat(data["skilled-hourly-nzd-sgd-30-60"])
        : undefined,
      bid_hkd: data["skilled-hourly-hkd-200-400"]
        ? parseFloat(data["skilled-hourly-hkd-200-400"])
        : undefined,
      budget_range_usd_aud_cad: "25-50",
      budget_range_gbp: "18-36",
      budget_range_eur: "18-36",
      budget_range_inr: "1250-2500",
      budget_range_nzd_sgd: "30-60",
      budget_range_hkd: "200-400",
    },
  };

  await Biddingprice.findOneAndUpdate(
    { user: userId },
    { $set: formattedData },
    { new: true, upsert: true } // Create if not exists
  );

  res.redirect("/bidPrice");
});

router.get("/period", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/period";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  let periods = await Periods.find({ user: userId });
  res.render("period", { currentUrl: currentUrl, userAutoBid, periods });
});

const parseData = (body) => {
  const result = [];

  // Extract numbers from keys and sort by unique index
  const indices = Object.keys(body)
    .filter((key) => key.match(/\d+/)) // filter keys containing digits
    .map((key) => key.match(/\d+/)[0]) // extract the digits
    .filter((value, index, self) => self.indexOf(value) === index); // get unique indices

  indices.forEach((index) => {
    const obj = {
      lower: body[`lower[${index}]`],
      higher: body[`higher[${index}]`],
      period: body[`period[${index}]`],
    };
    result.push(obj);
  });

  return result;
};
router.post("/period", sessionChecker, async (req, res) => {
  let userId = req.session.user._id;
  // const parsedData = parseData(req.body);
  // Access the form data from req.body
  const lowerBidPrices = req.body.lower; // Array of lower bid prices
  const higherBidPrices = req.body.higher; // Array of higher bid prices
  const projectPeriods = req.body.period; // Array of project periods

  // Do whatever you need with the form data
  // console.log("Lower Bid Prices:", lowerBidPrices);
  // console.log("Higher Bid Prices:", higherBidPrices);
  // console.log("Project Periods:", projectPeriods);
  let parsedData = [];

  // Iterate over the arrays and create an object for each index
  for (let i = 0; i < lowerBidPrices.length; i++) {
    // Create an object for each index with the corresponding values
    let dataObject = {
      lower: lowerBidPrices[i],
      higher: higherBidPrices[i],
      period: projectPeriods[i],
    };

    // Push the created object into the parsedData array
    parsedData.push(dataObject);
  }

  // console.log("here=--->", parsedData);

  for (let index = 0; index < parsedData.length; index++) {
    let period = new Periods({
      lower: parsedData[index].lower,
      higher: parsedData[index].higher,
      period: parsedData[index].period,
      user: userId,
    });
    await period.save();
  }
  res.redirect("/period");
});
router.post("/moveUp/:id", sessionChecker, async (req, res) => {
  try {
    const category = await TemplateCategories.findById(req.params.id);
    const previousCategory = await TemplateCategories.findOne({
      position: { $lt: category.position },
    }).sort({ position: -1 });

    if (previousCategory) {
      const tempPosition = category.position;
      category.position = previousCategory.position;
      previousCategory.position = tempPosition;

      await category.save();
      await previousCategory.save();
    }

    res.redirect("/tcats");
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});
router.get("/moveUp/:id", sessionChecker, async (req, res) => {
  try {
    console.log("HERE IN MOVEUP---->");
    const category = await TemplateCategories.findById(req.params.id);
    const previousCategory = await TemplateCategories.findOne({
      position: { $lt: category.position },
    }).sort({ position: -1 });

    if (previousCategory) {
      const tempPosition = category.position;
      category.position = previousCategory.position;
      previousCategory.position = tempPosition;

      await category.save();
      await previousCategory.save();
    }

    res.redirect("/tcats");
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});
router.get("/admin/dashboard", isAdmin, async (req, res) => {
  let users = await Users.find({ isAdmin: false });
  let usersOnTrial = await Users.find({ subscriptionType: "trial" });
  let usersOnMonthly = await Users.find({ subscriptionType: "monthly" });
  let usersOnSemiAnnual = await Users.find({ subscriptionType: "semi-annual" });
  let usersOnAnnual = await Users.find({ subscriptionType: "annual" });
  let usersOnNotSubscribed = await Users.find({
    subscriptionType: "not-subscribed",
  });
  // console.log("users on trial ", usersOnTrial.length);
  let userlength = users.length;
  let userOnTrialLength = usersOnTrial.length;
  let userOnMonthlyLength = usersOnMonthly.length;
  let userOnSemiAnnualLength = usersOnSemiAnnual.length;
  let userOnAnnualLength = usersOnAnnual.length;
  let userOnNotSubscribedLength = usersOnNotSubscribed.length;

  res.render("adminDashboard", {
    userlength,
    userOnTrialLength,
    userOnMonthlyLength,
    userOnSemiAnnualLength,
    userOnAnnualLength,
    userOnNotSubscribedLength,
  });
});
router.get("/admin/logout", isAdmin, async (req, res) => {
  delete req.session.admin;
  res.redirect("/login");
});
router.post("/admin/chatGptBid", isAdmin, async (req, res) => {
  const { userId, aiBid } = req.body;

  try {
    // console.log("userId: ", userId);
    // console.log("aiBid: ", aiBid);

    // Find user by ID
    const user = await Users.findById(userId);

    if (!user) {
      // If user is not found, send a 404 error response
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Update user aiBid based on the value of aiBid
    user.aiBid = aiBid;

    // Save the user document
    await user.save();
    console.log("user: ", user);

    // Redirect to the totalUsers page
    res.redirect("/admin/totalUsers");
  } catch (error) {
    // Log the error for debugging purposes
    console.error("Error updating user AI Bid status:", error);

    // Send an error response with a status code and message
    res
      .status(500)
      .json({ success: false, message: "Failed to update AI Bid status" });
  }
});
router.get("/admin/totalUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { isAdmin: false };

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTotalUsers view and pass the users data, pagination info, and search query to it
    res.render("adminTotalUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
//
function formatDate(dateString) {
  const date = new Date(dateString);
  const day = date.getDate();
  const month = date.toLocaleString("default", { month: "short" });
  const year = date.getFullYear();
  return `${month} ${day} ${year}`;
}
// Route handler for admin/editDates
router.get("/admin/editDates", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { isAdmin: false };

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Convert subscription dates to JavaScript Date objects and format them
    users.forEach((user) => {
      user.subscriptionStartDate = formatDate(user.subscriptionStartDate);
      user.subscriptionEndDate = formatDate(user.subscriptionEndDate);
    });

    // Count total number of users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminDates view and pass the users data, pagination info, and search query, along with the formatDate function, to it
    res.render("adminDates", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
      formatDate,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.post("/admin/editDates", isAdmin, async (req, res) => {
  try {
    // console.log("req bode", req.body);
    const dateString = req.body.selectedDate;
    const parsedDate = new Date(dateString);
    const formattedDate = parsedDate.toISOString();
    let user = await Users.findById(req.body.userId);
    if (user) {
      user.subscriptionEndDate = formattedDate;
      await user.save();
      // Respond with a success message
      res.status(200).json({
        success: true,
        message: `User ${user.username} Have  ${user.newSubscriptionType} subscription.`,
      });
    } else {
      // Handle case where user is not found
      res.status(404).json({ success: false, message: "User not found." });
    }
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/editSubscription", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { isAdmin: false };

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTotalUsers view and pass the users data, pagination info, and search query to it
    res.render("adminSubscription", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.post("/admin/editSubscription", isAdmin, async (req, res) => {
  try {
    let user = await Users.findById(req.body.userId);
    if (user) {
      user.subscriptionType = req.body.newSubscriptionType;
      await user.save();
      // Respond with a success message
      res.status(200).json({
        success: true,
        message: `User ${user.username} Have  ${user.newSubscriptionType} subscription.`,
      });
    } else {
      // Handle case where user is not found
      res.status(404).json({ success: false, message: "User not found." });
    }
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/bidsAllowed", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { isAdmin: false };

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTotalUsers view and pass the users data, pagination info, and search query to it
    res.render("adminBidsAllowed", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.post("/admin/bidsAllowed", isAdmin, async (req, res) => {
  try {
    // console.log("req body", req.body);

    let user = await Users.findById(req.body.userId);
    if (user) {
      user.bidsAllow = req.body.newValue;
      await user.save();
      // Respond with a success message
      res.status(200).json({
        success: true,
        message: `User ${user.username} Have  ${user.bidsAllow} remaining.`,
      });
    } else {
      // Handle case where user is not found
      res.status(404).json({ success: false, message: "User not found." });
    }
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/blockUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { isAdmin: false };

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTotalUsers view and pass the users data, pagination info, and search query to it
    res.render("adminBlockUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.post("/admin/blockUsers", isAdmin, async (req, res) => {
  try {
    // console.log("queru ", req.query);
    // console.log(" parameter", req.params);
    // console.log("body", req.body);
    let user = await Users.findById(req.body.userId);
    if (user) {
      user.isLocked = req.body.isLocked;
      user.autoBid = false;
      await user.save();
      // Respond with a success message
      res.status(200).json({
        success: true,
        message: `User ${user.username} is now ${
          user.isLocked ? "blocked" : "unblocked"
        }.`,
      });
    } else {
      // Handle case where user is not found
      res.status(404).json({ success: false, message: "User not found." });
    }
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/trialUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { subscriptionType: "trial", isAdmin: false }; // Fetch only trial users

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch trial users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of trial users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTrialUsers view and pass the users data, pagination info, and search query to it
    res.render("adminTrialUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching trial users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/monthlyUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { subscriptionType: "monthly", isAdmin: false }; // Fetch only trial users

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch trial users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of trial users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTrialUsers view and pass the users data, pagination info, and search query to it
    res.render("adminMonthlyUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching trial users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/semiAnnualUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { subscriptionType: "semi-annual", isAdmin: false }; // Fetch only trial users

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch trial users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of trial users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTrialUsers view and pass the users data, pagination info, and search query to it
    res.render("adminSemiAnnualUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching trial users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/annualUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { subscriptionType: "annual", isAdmin: false }; // Fetch only trial users

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch trial users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of trial users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTrialUsers view and pass the users data, pagination info, and search query to it
    res.render("adminAnnualUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching trial users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/notSubscribedUsers", isAdmin, async (req, res) => {
  try {
    // Get search query parameter from the frontend
    const searchQuery = req.query.searchQuery;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    // Construct the search query
    const query = { subscriptionType: "not-subscribed", isAdmin: false }; // Fetch only trial users

    // If search query exists, add search conditions to the query
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for username
        { email: { $regex: searchQuery, $options: "i" } }, // Case-insensitive search for email
        // Add more fields to search here if needed
      ];
    }

    // Fetch trial users matching the search query from the database
    const users = await Users.find(query).skip(skip).limit(limit);

    // Count total number of trial users matching the search query
    const totalUsers = await Users.countDocuments(query);

    // Calculate total pages for pagination
    const totalPages = Math.ceil(totalUsers / limit);

    // Render the adminTrialUsers view and pass the users data, pagination info, and search query to it
    res.render("adminNotSubscribedUsers", {
      users,
      currentPage: page,
      totalPages,
      searchQuery,
    });
  } catch (error) {
    // Handle any errors that occur during database query
    console.error("Error fetching trial users:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/admin/passChange", isAdmin, (req, res) => {
  res.render("adminPassChange");
});
router.get("/admin/passwordChanged", (req, res) => {
  // Render a view or send a response indicating that the password change was successful
  res.render("adminPassChange"); // Assuming you have a view file named passwordChanged.ejs
});
router.post("/admin/changePassword", isAdmin, async (req, res) => {
  try {
    console.log("session", req.session);
    console.log("password is ", req.session.admin.password);
    let userCurrentPassword = req.session.admin.password;
    let enteredOldPassword = req.body.old_password;
    let enteredNewPassword = req.body.new_password;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(enteredNewPassword, saltRounds);
    const isMatch = await bcrypt.compare(
      enteredOldPassword,
      userCurrentPassword
    );

    if (!isMatch) {
      console.log("Old password does not match");
      return res.redirect("/admin/passwordChanged?error=oldPassword");
    }

    const user = await Users.findOne({ _id: req.session.admin._id });
    if (user) {
      user.password = hashedPassword;
      await user.save();
      console.log("Password updated successfully");
    } else {
      console.log("User not found");
      return res.redirect("/changePassword?error=userNotFound");
    }

    // Redirect the user to a success page with a success message
    return res.redirect("/admin/passwordChanged?success=true");
  } catch (error) {
    console.error("Error updating password:", error);
    return res.redirect("/changePassword?error=unknown");
  }
});
router.get("/admin/changeInfo", isAdmin, async (req, res) => {
  // Render a view or send a response indicating that the password change was successful
  let userId = req.session.admin._id;
  const userData = await Users.find({ _id: userId });
  // console.log("userData", userData);
  res.render("adminInfo", { userData }); // Assuming you have a view file named passwordChanged.ejs
});
router.post("/admin/get-user-bids", isAdmin, async (req, res) => {
  let userId = req.body.userId;
  // Find all projects with the given userId
  const userProjects = await Projects.find({ user: userId });
  // console.log("her is userProjects", userProjects);
  // Send the user projects data to the frontend
  res.json({ userProjects });
});
router.post("/admin/changeInfo", isAdmin, async (req, res) => {
  try {
    // console.log("req body here", req.body);

    const user = await Users.findOne({ _id: req.session.admin._id });
    if (user) {
      user.email = req.body.email;
      user.phone = req.body.phone;
      user.skype = req.body.skype;
      user.telegram = req.body.telegram;
      await user.save();
      req.session.user.adminEmail = user.email;
      req.session.user.adminPhone = user.phone;
      req.session.user.adminSkype = user.skype;
      req.session.user.adminTelegram = user.telegram;
    }

    // Redirect the user to a success page with a success message
    return res.redirect("/admin/changeInfo?success=true");
  } catch (error) {
    console.error("Error updating password:", error);
    return res.redirect("/admin/changeInfo?error=unknown");
  }
});

// Move row down
router.get("/moveDown/:id", sessionChecker, async (req, res) => {
  try {
    const category = await TemplateCategories.findById(req.params.id);
    const nextCategory = await TemplateCategories.findOne({
      position: { $gt: category.position },
    }).sort({ position: 1 });

    if (nextCategory) {
      const tempPosition = category.position;
      category.position = nextCategory.position;
      nextCategory.position = tempPosition;

      await category.save();
      await nextCategory.save();
    }

    res.redirect("/tcats");
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/tcats", sessionChecker, async (req, res) => {
  try {
    const currentUrl = req.originalUrl || "/tcats";
    let userId = req.session.user._id;
    let user = await Users.findById(userId);
    let userAutoBid = user.autoBid ? "ON" : "Off";
    const allCategory = await TemplateCategories.find({ user: userId }).sort({
      position: 1,
    });
    // console.log("here is all categories----->", allCategory);
    // Render the 'tcats' template and pass the data to it
    res.render("tcats", {
      currentUrl: currentUrl,
      userAutoBid,
      allCategory: allCategory,
    });
  } catch (error) {
    // Handle errors appropriately
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/deleteTCat/:id", sessionChecker, async (req, res) => {
  const catId = req.params.id;
  try {
    // Find the category by ID and delete it
    await TemplateCategories.findByIdAndDelete(catId);
    const allCategory = await TemplateCategories.find();
    // res.render("tcats", { allCategory: allCategory }); // Send success response
  } catch (error) {
    console.error("Error deleting category:", error);
    res.sendStatus(500); // Send error response
  }
});

router.get("/addtcat", sessionChecker, (req, res) => {
  res.render("addTcat");
});

router.post("/addtcat", sessionChecker, async (req, res) => {
  // console.log("here is req body of add category form---->", req.body);
  let userId = req.session.user._id;
  let template = new TemplateCategories({
    name: req.body.name,
    always_include: req.body.always_include,
    position: req.body.position,
    user: userId,
  });
  await template.save();
  res.redirect("/tcats");
});

router.get("/temp", sessionChecker, async (req, res) => {
  const currentUrl = req.originalUrl || "/temp";
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  const allTemplates = await Templates.find({ userId: userId }).populate(
    "category"
  );
  // console.log("here are templates------->", allTemplates);
  res.render("temp", {
    currentUrl: currentUrl,
    userAutoBid,
    templates: allTemplates,
  });
});
router.delete("/delete/template/:id", sessionChecker, async (req, res) => {
  const templateId = req.params.id;
  try {
    // Find the template by ID and delete it
    await Templates.findByIdAndDelete(templateId);
    res.sendStatus(200); // Send success response
  } catch (error) {
    console.error("Error deleting template:", error);
    res.sendStatus(500); // Send error response
  }
});
router.get("/edit/template/:id", sessionChecker, async (req, res) => {
  const tempId = req.params.id;

  try {
    let userId = req.session.user._id;
    let userId1 = req.session.user._id;
    let user2 = await Users.findById(userId1);
    let userAutoBid = user2.autoBid ? "ON" : "Off";
    const allTemplates = await Templates.find({ userId: userId }).populate(
      "category"
    );
    // Find the template by ID
    const template = await Templates.findById(tempId).populate("category");
    // console.log("here is template", template);
    content = template.content;
    // console.log("here is content", content);
    categoryName = template.category.name;
    categoryValue = template.category._id;
    // console.log("here is categoryName", categoryName);

    // console.log("here is id in edit templates", userId);
    // Assuming you have a variable named 'categories' that contains all template categories
    const categories = await TemplateCategories.find({ user: userId });

    let user;
    try {
      user = await Users.findById(userId);
    } catch (error) {
      console.error("Error fetching user:", error);
      // Handle the error (e.g., send an error response or render an error page)
      // For example: return res.status(500).send('Internal Server Error');
    }

    // If user is null or undefined, set userSkills to an empty array
    const userSkills = user ? user.skills : [];
    // console.log(
    //   "here is recordOf template" +
    //     template +
    //     "here is categories " +
    //     categories +
    //     "here is userSkills",
    //   userSkills
    // );
    res.render("editTemplate", {
      userAutoBid,
      template,
      categories,
      userSkills,
      content,
      categoryName,
      categoryValue,
    });
  } catch (error) {
    console.error("Error finding template:", error);
    res.sendStatus(500); // Send error response
  }
});
router.post("/add/submitTemplate", sessionChecker, async (req, res) => {
  try {
    let data = req.body;
    let userId = req.session.user._id;
    let user = await Users.findById(userId);
    let userAutoBid = user.autoBid ? "ON" : "Off";
    // Create a new Template instance with the data from req.body
    const newTemplate = new Templates({
      content: data.content,
      skills: data["skills[]"], // Assign the skills array directly
      category: data.template_category_id, // Assuming template_category_id is the category ID
      // If SkillSets is also a reference to another model, provide its value accordingly
      SkillSets: data.skill_sets_id,
      userId: userId,
    });

    // Save the new template to the database
    await newTemplate.save();

    // console.log("Template saved:", newTemplate);
    const allTemplates = await Templates.find({ userId: userId }).populate(
      "category"
    );
    // console.log("here are templates------->", allTemplates);
    res.render("temp", { userAutoBid, templates: allTemplates });
  } catch (error) {
    console.error("Error saving template:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.post("/update/Template/:id", sessionChecker, async (req, res) => {
  // Extract the template ID from req.params
  const templateId = req.params.id;
  let userId = req.session.user._id;
  let user = await Users.findById(userId);
  let userAutoBid = user.autoBid ? "ON" : "Off";
  // Extract the updated data from req.body
  const data = req.body;

  // Assuming you have already extracted userId

  try {
    // Find the template by ID
    const template = await Templates.findById(templateId);

    // Update the template data
    template.content = data.content;
    template.skills = data.skills;
    template.category = data.template_category_id;
    template.userId = req.session.user._id;

    // Save the updated template
    await template.save();

    const allTemplates = await Templates.find({ userId: userId }).populate(
      "category"
    );
    // console.log("here are templates------->", allTemplates);
    res.render("temp", { userAutoBid, templates: allTemplates });
  } catch (error) {
    console.error("Error saving template:", error);
    res.status(500).send("Internal Server Error");
  }
});
router.get("/templateAdd", sessionChecker, async (req, res) => {
  let userId = req.session.user._id;
  const categories = await TemplateCategories.find({ user: userId });

  let user;
  try {
    user = await Users.findById(userId);
  } catch (error) {
    console.error("Error fetching user:", error);
    // Handle the error (e.g., send an error response or render an error page)
    // For example: return res.status(500).send('Internal Server Error');
  }

  // If user is null or undefined, set userSkills to an empty array
  const userSkills = user ? user.skills : [];

  res.render("addTemplate", { categories: categories, userSkills: userSkills });
});

router.get("/editTemp", sessionChecker, (req, res) => {
  res.render("editTemplate");
});

router.get("/passChange", sessionChecker, (req, res) => {
  res.render("passChange", {
    error: req.query.error,
    success: req.query.success,
  });
});
router.get("/passwordChanged", (req, res) => {
  // Render a view or send a response indicating that the password change was successful
  res.render("passChange"); // Assuming you have a view file named passwordChanged.ejs
});
router.post("/changePassword", sessionChecker, async (req, res) => {
  try {
    const enteredOldPassword = req.body.old_password;
    const enteredNewPassword = req.body.new_password;

    // Fetch the user from the database
    const user = await Users.findOne({ _id: req.session.user._id });

    if (!user) {
      console.log("User not found");
      return res.redirect("/passChange?error=userNotFound");
    }

    // Compare the entered old password with the stored password
    const isMatch = await bcrypt.compare(enteredOldPassword, user.password);

    if (!isMatch) {
      // console.log("Old password does not match");
      return res.redirect("/passChange?error=oldPassword");
    }

    // Hash the new password and update it in the database
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(enteredNewPassword, saltRounds);
    user.password = hashedPassword;
    await user.save();

    console.log("Password updated successfully");
    return res.redirect("/passChange?success=true");
  } catch (error) {
    console.error("Error updating password:", error);
    return res.redirect("/passChange?error=unknown");
  }
});

router.get("/guide", sessionChecker, (req, res) => {
  res.render("guide");
});
router.get("/fakeData", sessionChecker, async (req, res) => {
  console.log(req.body);
  let title = "for books";
  let username = "Waleed";
  const responseData = {
    status: "success",
    result: {
      id: 465980,
      bidder_id: 25957212,
      project_id: 16296493,
      retracted: false,
      amount: 600,
      period: 3,
      description:
        "Hello\n" +
        "We went through your project description and it seems like our team is a great fit for this job.\n" +
        "We are an expert team which have many years of experience on Job Skills.\n" +
        "Lets connect in chat so that We discuss further.\n" +
        "Thank You",
      project_owner_id: 25955725,
      submitdate: 1714740754,
      buyer_project_fee: null,
      time_submitted: 1714740754,
      highlighted: null,
      sponsored: null,
      milestone_percentage: 50,
      award_status_possibilities: null,
      award_status: null,
      paid_status: null,
      complete_status: null,
      reputation: null,
      time_awarded: null,
      frontend_bid_status: null,
      hireme_counter_offer: null,
      shortlisted: null,
      score: null,
      distance: null,
      negotiated_offer: null,
      hidden: null,
      hidden_reason: null,
      time_accepted: null,
      paid_amount: null,
      hourly_rate: null,
      sealed: false,
      complete_status_changed_time: null,
      award_status_changed_time: null,
      is_location_tracked: null,
      rating: null,
      quotations: null,
      pitch_id: null,
      sales_tax: null,
      profile_id: null,
    },
    request_id: "19fed637c2a7541be46dd570b68a2447",
  };

  if (responseData.status !== "error") {
    let dateString = responseData.result.submitdate;
    const date = new Date().toISOString().split("T")[0];
    const newRecord = await Projects.create({
      // Define the fields of the new record
      projectTitle: title,
      bidAmount: responseData.result.amount,
      userName: username,
      time: date,
      user: req.session.user._id,
      // Add more fields as needed
    });
  }
  return res.status(200).json(responseData);
});

router.get("/logout", async (req, res) => {
  delete req.session.user;
  res.redirect("/login");
});
router.get("/emptyRecord", async (req, res) => {
  let id = req.session.user._id;

  let updatingStartTime = await Users.findOneAndUpdate(
    { _id: id },
    {
      $set: {
        bidStartTime: "",
        bidEndTime: "",
        breakTime: "",
      },
    },
    { new: true }
  );
});

router.get("/chatgpt", async (req, res) => {
  console.log("req body here : ", req.body);
  try {
    const prompt =
      req.query.prompt ||
      "Once upon a time in a land far, far away, there was a small village where...";
    const API_KEY = "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";
    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 150,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );

    const reply = response.data.choices[0].message.content;
    res.json({ reply });
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ error: "An error occurred while processing your request." });
  }
});

async function getChatGptResponse(prompt) {
  const API_KEY = process.env.chatGptKey;

  try {
    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 150,
      },
      {
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );

    const reply = response.data.choices[0].message.content.trim();
    return reply;
  } catch (error) {
    console.error("Error:", error);
    // throw new Error("An error occurred while processing your request.");
  }
}

router.post("/admin/resetPassword", isAdmin, async (req, res) => {
  try {
    let userId = req.body.userId;
    // console.log("user id ", userId);

    // Function to generate a random 14-character password
    function generateRandomPassword(length) {
      return crypto.randomBytes(length).toString("hex").slice(0, length);
    }

    const newPassword = generateRandomPassword(14); // Generate a 14-character password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    const user = await Users.findOne({ _id: userId });
    // console.log("here is user ", user);

    if (user) {
      user.password = hashedPassword;
      await user.save();
      // console.log("Password updated successfully");

      // Send the new password to the frontend
      res.status(200).send({
        message: "Password reset successfully!",
        newPassword: newPassword, // Include the new password in the response
      });
    } else {
      res.status(404).send({ message: "User not found." });
    }
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).send({ message: "Error resetting password." });
  }
});

async function processAutoBids() {
  try {
    const usersWithAutoBidOn = await Users.find({ autoBid: true });
    const usersWithAutoBidOnIds = usersWithAutoBidOn.map((user) => user._id);

    for (let i = 0; i < usersWithAutoBidOnIds.length; ) {
      console.log("Current user index:", i);
      // Get user ID from session
      const userId = usersWithAutoBidOnIds[i];

      // Fetch user details using the user ID
      let user = await Users.findById(userId);
      console.log("user id: ", user._id);
      // Extract access token from user details
      let accessToken = user.access_token;
      let userSkills = user.skills;
      const userSkillsWithValue = userSkills
        .map((skill) => {
          const matchedSkill = allSkills.find((s) => s.tag === skill);
          return matchedSkill ? { skill, value: matchedSkill.value } : null;
        })
        .filter(Boolean);
      const userSkillValues = userSkillsWithValue.map((skill) =>
        Number(skill.value)
      );
      // Extract excluded skills and excluded countries from user details
      let excludedSkills = user.excluded_skills;
      let excludedCountries = user.excluded_countries;
      let clientPaymentVerified = user.payment_verified;
      let clientEmailVerified = user.email_verified;
      let clientDepositMade = user.deposit_made;
      let minimumBudgetFix = parseInt(user.minimum_budget_fixed);
      let minimumBudgetHourly = parseInt(user.minimum_budget_hourly);

      // Construct headers with access token
      const headers = {  'content-type': 'application/json',"freelancer-oauth-v1": accessToken };
      let bidEndTime2;
      let brakeTime2;
      console.log("user: ", user);
      if (user.bidEndTime) {
        bidEndTime2 = new Date(user.bidEndTime);
        console.log("Bid End Time:", bidEndTime2);
      }
      if (user.breakTime) {
        brakeTime2 = new Date(user.breakTime);
        console.log("Bid End Time:", brakeTime2);
      }
      let bidsAllowed = user.bidsAllow;
      console.log("bits allowed are", bidsAllowed);
      const currentTime = new Date();
      console.log("user bid end time : ");
      console.log(
        "here is user current time : " +
          currentTime +
          " here is user bid end time : " +
          bidEndTime2
      );
      console.log(
        "here is user current time : " +
          currentTime +
          " here is user break time : " +
          brakeTime2
      );
      if (!brakeTime2 || currentTime > brakeTime2) {
        if (!bidEndTime2 || currentTime < bidEndTime2) {
          console.log("user bid start time in start : ", user.bidStartTime);
          let updatingStartTime = user.bidStartTime;

          if (!user.bidStartTime) {
            const currentTime2 = new Date();
            const updatedUser = await Users.findOneAndUpdate(
              { _id: user._id },
              { $set: { bidStartTime: currentTime2 } },
              { new: true }
            );
            updatingStartTime = updatedUser.bidStartTime;
          }

          let firstBrakeTime;
          if (updatingStartTime) {
            let timeInterval = parseInt(user.timeInterval); // Use `let` here
            if (timeInterval === 1) {
              timeInterval = 2; // Reassignment is now allowed
            }
            const timeIntervalMilliseconds = timeInterval * 60000;
            console.log("bidStart time: ", updatingStartTime);
            // Add the time limit in minutes to the bid start time
            firstBrakeTime = new Date(
              updatingStartTime.getTime() + timeIntervalMilliseconds + 2000
            );
          }

          if (!user.breakTime && firstBrakeTime) {
            await Users.findOneAndUpdate(
              { _id: user._id },
              { $set: { breakTime: firstBrakeTime } },
              { new: true }
            );
          } else if (user.breakTime) {
            let timeInterval = parseInt(user.timeInterval);

            // Check if user.timeInterval is 1, if so, make it 1.5
            if (timeInterval === 1) {
              timeInterval = 2;
            }
            const secondBrakeTime = new Date(
              user.breakTime.getTime() + timeInterval * 60000
            );
            await Users.findOneAndUpdate(
              { _id: user._id },
              { $set: { breakTime: secondBrakeTime } },
              { new: true }
            );
          }

          if (bidsAllowed > 0) {
            // API endpoint for fetching projects
            const url = "https://freelancer.com/api/projects/0.1/projects/all/";

            // Parameters for the API request
            const params = {
              jobs: userSkillValues,
              min_avg_price: 10,
              project_statuses: ["active"],
              full_description: true,
              job_details: true,
              user_details: true,
              location_details: true,
              user_status: true,
              user_reputation: true,
              user_country_details: true,
              user_display_info: true,
              user_membership_details: true,
              user_financial_details: true,
              compact: true,
            };

            // Make request to fetch projects
            const response = await axios.get(url, {
              params: params,
              headers: headers,
            });

            // Process response data
            const responseData = response.data;
            const projects = responseData.result.projects;

            // Extract user details for project owners
            const ownerIds = projects.map((project) => project.owner_id);

            const projectsDetails = await Promise.all(
              ownerIds.map(async (ownerId) => {
                if (!isNaN(ownerId)) {
                  try {
                    const ownerUrl = `https://freelancer.com/api/users/0.1/users/${ownerId}/`;
                    const ownerResponse = await axios.get(ownerUrl, {
                      params: {
                        jobs: true,
                        reputation: true,
                        employer_reputation: true,
                        reputation_extra: true,
                        employer_reputation_extra: true,
                        job_ranks: true,
                        staff_details: true,
                        completed_user_relevant_job_count: true,
                      },
                      headers: headers,
                    });
                    return ownerResponse.data.result;
                  } catch (error) {
                    if (error.response && error.response.status === 404) {
                      console.error(`User with ownerId ${ownerId} not found.`);
                      return null; // Handle 404 error gracefully
                    } else {
                      console.error(
                        `Error fetching user details for ownerId ${ownerId}:`,
                        error
                      );
                      throw error; // Rethrow other errors to handle them later
                    }
                  }
                } else {
                  return null;
                }
              })
            );

            const projects2 = responseData.result.projects.map(
              (project, index) => ({
                projectid: project.id,
                type: project.type,
                description: project.description,
                title: project.title,
                currencyName: project.currency.name,
                currencySign: project.currency.sign,
                bidCount: project.bid_stats.bid_count,
                bidAverage: project.bid_stats.bid_avg,
                jobNames: project.jobs.map((job) => job.name),
                minimumBudget: project.budget.minimum,
                maximumBudget: project.budget.maximum,
                country: project.location.country.flag_url,
                fullName: projectsDetails[index]?.username,
                displayName: projectsDetails[index]?.public_name,
                ownerCountry: projectsDetails[index]?.location?.country?.name,
                payment: projectsDetails[index]?.status?.payment_verified,
                email: projectsDetails[index]?.status?.email_verified,
                deposit_made: projectsDetails[index]?.status?.deposit_made,
                identity_verified:
                  projectsDetails[index]?.status?.identity_verified,
                countryShortName: projectsDetails[index]?.timezone?.country,
                currencyCode: project.currency.code,
              })
            );

            const filteredProjects2 = projects2.filter((project) => {
              // Convert project's countryShortName to lowercase for case-insensitive comparison
              const projectCountry = project.countryShortName
                ? project.countryShortName.toLowerCase()
                : "";

              // Check if project's countryShortName matches any excluded country (case-insensitive)
              if (
                excludedCountries.some(
                  (country) => country.toLowerCase() === projectCountry
                )
              ) {
                return false; // Exclude project
              }

              // Check if project's jobNames include any excluded skill (case-insensitive)
              if (
                project.jobNames.some((skill) =>
                  excludedSkills.includes(skill.toLowerCase())
                )
              ) {
                return false; // Exclude project
              }

              // Check if clientPaymentVerified is 'yes'
              if (clientPaymentVerified == "yes" && project.payment == null) {
                return false; // Exclude project
              }

              // Check if clientEmailVerified is 'yes'
              if (clientEmailVerified == "yes" && project.email !== true) {
                return false; // Include project
              }

              // Check if clientDepositMade is 'yes'
              if (clientDepositMade == "yes" && project.deposit_made == null) {
                return false; // Exclude project
              }

              // Additional filters based on project type (fixed or hourly)
              if (
                project.type == "fixed" &&
                project.minimumBudget <= minimumBudgetFix
              ) {
                return false; // Exclude project
              }

              if (
                project.type == "hourly" &&
                project.minimumBudget <= minimumBudgetHourly
              ) {
                return false; // Exclude project
              }

              return true; // Include project
            });

            const templates = await Templates.find({ userId: userId }).populate(
              "category"
            );

            console.log("here are templates------>", templates);

            // Function to randomly decide inclusion for templates with always_include = false
            const randomlyInclude = (probability) =>
              Math.random() < probability;

            // Filter templates by category, deciding randomly for always_include = false
            const filteredTemplates = templates.filter((template) => {
              if (
                template.category &&
                template.category.always_include === true
              ) {
                console.log(
                  `Including template: ${template._id} (always_include = true)`
                );
                return true; // Always include
              } else if (
                template.category &&
                template.category.always_include === false
              ) {
                const include = randomlyInclude(0.5); // 50% chance to include
                console.log(
                  `Template: ${template._id} (always_include = false) included: ${include}`
                );
                return include;
              }
              console.log(
                `Excluding template: ${template._id} (category not defined or always_include not specified)`
              );
              return false; // Exclude if category is not defined or always_include is not specified
            });

            // Group and sort filteredTemplates by category position
            const groupedAndSortedTemplates = filteredTemplates.reduce(
              (acc, template) => {
                const categoryId = template.category._id.toString();
                if (!acc[categoryId]) {
                  acc[categoryId] = {
                    position: template.category.position,
                    templates: [],
                  };
                }
                acc[categoryId].templates.push(template);
                return acc;
              },
              {}
            );

            // Convert object to array and sort by position
            const sortedCategories = Object.values(
              groupedAndSortedTemplates
            ).sort((a, b) => a.position - b.position);
            console.log(sortedCategories);

            // Function to get final content from templates for a project
            const getFinalContentForProject = (
              project,
              templates,
              ownerName,
              userSkills
            ) => {
              return templates.reduce((acc, category) => {
                const randomTemplateIndex = Math.floor(
                  Math.random() * category.templates.length
                );
                const selectedTemplate =
                  category.templates[randomTemplateIndex];
                const matchingSkills = project.jobNames.filter((jobName) =>
                  userSkills.includes(jobName)
                );

                const replacedContent = selectedTemplate.content
                  .replace(/{{Project Title}}/g, project.title)
                  .replace(/{{Owner Name}}/g, ownerName)
                  .replace(/{{Owner Full Name}}/g, project.displayName)
                  .replace(
                    /{{Matching Job Skills}}/g,
                    matchingSkills.join(", ")
                  )
                  .replace(/{{Job Skills}}/g, userSkills.slice(0, 5).join(", "))
                  .replace(
                    /{{Owner First Name}}/g,
                    ownerName.split(" ")[0] || ownerName
                  )
                  .replace(/{{Country}}/g, project.ownerCountry)
                  .replace(/{{NewLine}}/g, "\n");

                return acc + replacedContent + "\n"; // Add a newline after each template
              }, "");
            };

            console.log("Here is user just before making content: ", user);
            const userSkills = user.skills;
            const filteredProjectDetails = filteredProjects2.map((project) => {
              const ownerName = project.fullName || project.displayName || "";
              const finalContent = getFinalContentForProject(
                project,
                sortedCategories,
                ownerName,
                userSkills
              );

              return {
                projectid: project.projectid,
                currencyCode: project.currencyCode,
                type: project.type,
                title: project.title,
                bidAverage: project.bidAverage,
                minimumBudget: project.minimumBudget,
                maximumBudget: project.maximumBudget,
                fullName: project.fullName,
                displayName: project.displayName,
                jobNames: project.jobNames,
                description: finalContent,
                projectDescription: project.description,
                bidderName: user.username,
                bidderskills: user.skills,
              };
            });

            // console.log(
            //   "Final project details with descriptions:",
            //   filteredProjectDetails
            // );
            const numBids = Math.min(bidsAllowed, user.bidsLimit);

            const currentTime = new Date();
            const timeLimitInMinutes = parseInt(user.timeLimit);
            let userNew = await Users.findById(userId);
            // Add the time limit in minutes to the current time
            console.log(
              "after new time : ",
              userNew.bidStartTime,
              timeLimitInMinutes
            );
            const bidEndTime = new Date(
              userNew.bidStartTime.getTime() + timeLimitInMinutes * 60000
            );
            let whenToStop = new Date(userNew.bidEndTime).getTime();
            let latestTime = Date.now();

            if (isIntervalHit(user.bidStartTime, user.timeInterval)) {
              for (let i = 0; i < filteredProjectDetails.length; i++) {
                const project = filteredProjectDetails[i];
                console.log("here is project", project);
                const extractedData = {
                  title: project.title,
                  jobNames: project.jobNames,
                  projectDescription: project.projectDescription,
                  myName: project.bidderName,
                  mySkills: project.bidderskills,
                  clientName: project.fullName,
                  clientDisplayName: project.displayName,
                  currencyCode: project.currencyCode,
                  type: project.type,
                  minimumBudget: project.minimumBudget,
                  maximumBudget: project.maximumBudget,
                  bidAverage: project.bidAverage,
                };
                console.log("extrected data: ", extractedData);
                console.log("user ai bid value : ", user.aiBid);
                if (user.aiBid) {
                  const prompt = `I am providing examples of proposals to guide the tone and structure for this task:
                              EXAMPLE 1
                              As a seasoned cryptocurrency and technology enthusiast with over five years of experience in fields such as Bitcoin, Mobile Applications, and PHP, I am confident that I am the ideal candidate for this urgent project. My expertise in Android/iOS app development, web and mobile application design—from E-commerce to Cryptocurrencies—allows me to offer an innovative and effective Social Media Engagement and Cryptocurrency Performance web application.
                              
                              With extensive experience in developing Social Networking apps, Mobile Ads integration, E-learning tools, and more, I excel at understanding clients' needs and delivering exceptional results. Expect consistent communication, reliable support, and detailed status reports. Partnering with me means your project will be handled with professionalism and expertise. Thank you!
                              
                              EXAMPLE 2
                              My name is Stelian, and I am a full-stack developer with over a decade of experience. I've built numerous applications using various technical stacks, with extensive work in C# and JavaScript—key languages for your project.
                              
                              In addition to my C# programming skills, I have a strong background in Windows desktop environments. My experience aligns perfectly with decrypting and modifying complex programs. Though I may not have access to specific codes, my expertise in debugging and reverse engineering will be instrumental. My familiarity with AWS deployment and Linux System Administration further enhances my ability to optimize project performance and security.
                              
                              Now, keeping these examples in mind, please create a proposal for a project I found on Freelancer.com. Here are the details:
                              Title of project: ${extractedData.title}
                              skills which are required for project: ${
                                extractedData.jobNames
                              }
                              Description of project: ${
                                extractedData.projectDescription
                              }
                              Client name who posted it : ${
                                extractedData.clientName ||
                                extractedData.clientDisplayName
                              }
                               My Name: ${extractedData.myName}
                               My Skills: ${extractedData.mySkills}
                              
                              Write a proposal that follows the structure and tone of the provided examples. The proposal should be written in a conversational, human-like manner, not exceed 200 words, and include a closing statement inviting further discussion. Provide only the main body of the proposal, starting with the greeting and ending with the closing statement, without including the title or other details.`;
                  const result = await getChatGptResponse(prompt);

                  if (result) {
                    console.log(" chat 3 ", result);
                    project.description = result; // Replace project description with the generated proposal
                  }
                }
                // Extract project details
                const {
                  projectid,
                  minimumBudget,
                  maximumBudget,
                  description,
                  bidAverage,
                  title,
                  fullName,
                  currencyCode,
                  type,
                } = project;

                const filterObject = await Biddingprice.findOne({
                  user: user._id,
                });

                let bidderid = parseInt(user.id);
                let projectID = parseInt(projectid);

                const currencyMap = {
                  USD: "usd_aud_cad",
                  AUD: "usd_aud_cad",
                  CAD: "usd_aud_cad",
                  GBP: "gbp",
                  EUR: "eur",
                  INR: "inr",
                  SGD: "nzd_sgd",
                  NZD: "nzd_sgd",
                  HKD: "hkd",
                };
                const bidValue = getBidValue(project, filterObject, user);
                console.log("project: ", project);
                console.log("filterObject :", filterObject);
                console.log("user :", user);
                console.log("Bidder ID:", bidderid);
                console.log("Project ID:", projectID);
                console.log("maximum Money:", maximumBudget);
                console.log("Bid Money:", bidValue);
                console.log("project Description: ", description);
                // Prepare the bid request body
                const bidRequestBody = {
                  project_id: projectID,
                  bidder_id: bidderid,
                  amount: bidValue,
                  period: 3,
                  milestone_percentage: 50,
                  description: description,
                };

                // Make the POST request to Freelancer API
                const response = await fetch(
                  `https://www.freelancer.com/api/projects/0.1/bids/`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      "freelancer-oauth-v1": accessToken,
                    },
                    body: JSON.stringify(bidRequestBody),
                  }
                );

                // Parse the JSON response
                const responseData = await response.json();

                // Log response
                console.log("Bid Response: ", responseData);
                if (
                  responseData.error_code ===
                  "ProjectExceptionCodes.DUPLICATE_BID"
                ) {
                  console.log(
                    "Already bid on this project. Trying the next one..."
                  );
                  continue;
                } else {
                  console.log("User Id :", user._id);
                  if (responseData.status == "error") {
                    const date = new Date().toISOString().split("T")[0];
                    const newRecord = await Projects.create({
                      // Define the fields of the new record
                      bidDescription: responseData.message,
                      projectTitle: project.title,
                      bidAmount: bidValue,
                      userName: project.fullName,
                      status: 1,
                      time: date,
                      user: user._id,
                      // Add more fields as needed
                    });
                    await Users.updateOne(
                      { _id: user._id },
                      {
                        $inc: {
                          bidsAllow: -1,
                          bidsLimit: -1,
                        },
                      }
                    );

                    if (user.bidsLimit <= 0) {
                      let updatingAutoBid = await Users.findOneAndUpdate(
                        { _id: user._id },
                        { $set: { autoBid: false } }, // Update operation to set the `bidStartTime` field
                        { new: true } // Option to return the updated document
                      );
                    }

                    console.log(
                      "bidEndTime on project FAILED: ",
                      user.bidEndTime
                    );
                    console.log(
                      "bidEndTime on project FAILED which was calculated: ",
                      bidEndTime
                    );

                    if (!user.bidEndTime) {
                      let updatingStartTime = await Users.findOneAndUpdate(
                        { _id: user._id },
                        {
                          $set: {
                            bidStartTime: currentTime,
                            bidEndTime: bidEndTime,
                          },
                        },
                        { new: true }
                      );
                    }
                    // Decrease bidsAllowed by 1 for the user if bid was successful
                  }

                  if (responseData.status !== "error") {
                    let dateString = responseData.result.submitdate;
                    const date = new Date().toISOString().split("T")[0];
                    const newRecord = await Projects.create({
                      // Define the fields of the new record
                      bidDescription: description,
                      projectTitle: title,
                      bidAmount: responseData.result.amount,
                      userName: fullName,
                      time: date,
                      user: user._id,
                      // Add more fields as needed
                    });
                    // Decrease bidsAllowed by 1 for the user if bid was successful
                    bidsAllowed = bidsAllowed - 1;

                    await Users.updateOne(
                      { _id: user._id },
                      {
                        $inc: {
                          bidsAllow: -1,
                          bidsLimit: -1,
                        },
                      }
                    );

                    if (user.bidsLimit <= 0) {
                      let updatingAutoBid = await Users.findOneAndUpdate(
                        { _id: user._id },
                        { $set: { autoBid: false } }, // Update operation to set the `bidStartTime` field
                        { new: true } // Option to return the updated document
                      );
                    }

                    console.log(
                      "bidEndTime on project success: ",
                      user.bidEndTime
                    );
                    console.log(
                      "bidEndTime on project success which was calculated: ",
                      bidEndTime
                    );
                    if (!user.bidEndTime) {
                      let updatingStartTime = await Users.findOneAndUpdate(
                        { _id: user._id },
                        {
                          $set: {
                            bidStartTime: currentTime,
                            bidEndTime: bidEndTime,
                          },
                        },
                        { new: true }
                      );
                    }
                  }
                  break;
                }
              }
            } else {
              console.log("is interval hit return false");
            }
          }

          console.log("updating time", user._id);
        } else {
          console.log(
            "setting auto bid off and end and start date empty for user fo user: ",
            user._id
          );
          let updatingAutoBid = await Users.findOneAndUpdate(
            { _id: user._id },
            {
              $set: {
                autoBid: false,
                bidEndTime: null,
                bidStartTime: null,
                breakTime: null,
              },
            },
            { new: true } // Option to return the updated document
          );
        }
      }
      console.log("Moving to the next user...");
      i++;
    }
    console.log("all users done");
    return "Processing complete for all users with autoBid on";
  } catch (error) {
    console.error("Error occurred:", error);
    throw error;
  }
}

// Function to calculate a fallback bid
function calculateFallbackBid(bidAverage, minimumBudget, maximumBudget, user) {
  let averageBid = parseInt(bidAverage);
  let lowRange = parseInt(user.lower_bid_range);
  let highRange = parseInt(user.higher_bid_range);
  const lowerValue = averageBid * (lowRange / 100);
  const higherValue = averageBid * (highRange / 100);
  let smallValue = averageBid - lowerValue;
  let largeValue = averageBid + higherValue;
  let randomValue = parseFloat(
    (smallValue + Math.random() * (largeValue - smallValue)).toFixed(2)
  );
  let bidMoney;
  if (maximumBudget) {
    bidMoney = parseInt(maximumBudget * 0.7);
  } else {
    bidMoney = parseInt(randomValue);
  }
  if (isNaN(bidMoney) || lowRange == 0 || highRange == 0) {
    bidMoney = parseFloat(averageBid);
  }
  return bidMoney;
}

// Function to determine the category of the project
function determineCategory(project, filterObject) {
  if (!filterObject) {
    console.error("filterObject is null or undefined");
    return null;
  }

  const { minimumBudget, currencyCode } = project;

  // Select filters based on project type
  let filters;

  if (project.type === "fixed") {
    filters = {
      micro_project: filterObject.micro_project,
      simple_project: filterObject.simple_project,
      very_small_project: filterObject.very_small_project,
      small_project: filterObject.small_project,
      large_project: filterObject.large_project,
    };
  } else if (project.type === "hourly") {
    filters = {
      basic_hourly: filterObject.basic_hourly,
      moderate_hourly: filterObject.moderate_hourly,
      standard_hourly: filterObject.standard_hourly,
      skilled_hourly: filterObject.skilled_hourly,
    };
  }

  let pricetocompare;
  // console.log(`Filters available: ${Object.keys(filters).join(", ")}`);

  for (let [key, filter] of Object.entries(filters)) {
    if (!filter) {
      console.warn(`Filter for ${key} is not defined`);
      continue;
    }

    const budgetType = filter.budget || filter.rate;
    if (budgetType === "lowest") {
      pricetocompare = minimumBudget;
    } else if (budgetType === "average") {
      pricetocompare = project.bidAverage;
    } else if (budgetType === "highest") {
      pricetocompare = project.maximumBudget;
    }

    const currencyKey = currencyCode.toLowerCase();
    const budgetRangeKey = `budget_range_${currencyKey}`;
    if (filter[budgetRangeKey]) {
      const [low, high] = filter[budgetRangeKey].split("-").map(Number);
      if (pricetocompare >= low && pricetocompare < high) {
        console.log(
          `Project falls under ${key} category with range ${low}-${high}`
        );
        return key; // Return the category key
      }
    }
  }
  console.log("No valid category found");
  return null; // Return null if no category is found
}

// Function to get bid value based on project and filters
function getBidValue(project, filterObject, user) {
  if (!filterObject) {
    return calculateFallbackBid(
      project.bidAverage,
      project.minimumBudget,
      project.maximumBudget,
      user
    );
  }

  const { currencyCode } = project;

  // Determine the category of the project
  const category = determineCategory(project, filterObject);

  if (category) {
    const filter = filterObject[category];
    if (!filter) {
      console.error(`No filter found for category: ${category}`);
      return calculateFallbackBid(
        project.bidAverage,
        project.minimumBudget,
        project.maximumBudget,
        user
      );
    }

    const budgetType = filter.budget || filter.rate;
    let pricetocompare;
    if (budgetType === "lowest") {
      pricetocompare = project.minimumBudget;
    } else if (budgetType === "average") {
      pricetocompare = project.bidAverage;
    } else if (budgetType === "highest") {
      pricetocompare = project.maximumBudget;
    }

    const currencyKey = currencyCode.toLowerCase();
    const budgetRangeKey = `budget_range_${currencyKey}`;
    if (filter[budgetRangeKey]) {
      const [low, high] = filter[budgetRangeKey].split("-").map(Number);
      if (pricetocompare >= low && pricetocompare < high) {
        const bidKey = `bid_${currencyKey}`;
        let bidValue = filter[bidKey];
        if (bidValue === 0 || bidValue === null) {
          const fallbackBid = calculateFallbackBid(
            project.bidAverage,
            project.minimumBudget,
            project.maximumBudget,
            user
          );
          return fallbackBid;
        }
        return bidValue;
      }
    }
  }

  // Use fallback logic if no valid bid value found in filters
  const fallbackBid = calculateFallbackBid(
    project.bidAverage,
    project.minimumBudget,
    project.maximumBudget,
    user
  );
  console.log(`Fallback bid value used: ${fallbackBid}`);
  return fallbackBid;
}

router.get("/api/projects", sessionChecker, async (req, res) => {
  try {
    const dateString = req.query.date;
    const date = new Date(dateString); // Parse the date string

    // Construct the start and end dates to cover the entire selected day in UTC
    const startDate = new Date(
      Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate())
    );
    const endDate = new Date(startDate);
    endDate.setUTCDate(endDate.getUTCDate() + 1); // Move to the next day in UTC
    const userId = req.session.user._id;

    // Query projects within the date range
    const projects = await Projects.find({
      time: {
        $gte: startDate,
        $lt: endDate,
      },
      user: userId,
    });

    projects.forEach((project) => {
      // Replace newline characters in the bidDescription field with a space
      project.bidDescription = project.bidDescription.replace(/\n/g, " ");
    });

    res.json(projects);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error" });
  }
});
router.get("/locked", async (req, res) => {
  if (req.session.user) {
    delete req.session.user;
  }
  res.render("locked");
});
router.post("/getBonus", async (req, res) => {
  try {
    let userId = req.session.user._id;
    let user = await Users.findOne({ _id: userId });

    // Check if user's email and phone are null
    if (!user.email && !user.phone) {
      // Update user's email and phone
      user.email = req.body.email;
      user.phone = req.body.phone;
      user.bidsAllow += 50;
      user.subscriptionEndDate.setDate(user.subscriptionEndDate.getDate() + 2);
      // Save the updated user
      await user.save();
      // Send success response to frontend
      res.status(200).json({
        message: "User information updated successfully.You got your bonus",
      });
    } else {
      // Send sorry message to frontend
      res
        .status(400)
        .json({ message: "We're sorry, user information cannot be updated." });
    }
  } catch (error) {
    console.error("Error updating user information:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});
router.get("/createAdmin", async (req, res) => {
  let name = "admin";
  let password = "$2a$10$OQdbnd.V7II6X6cQ.YrUVeQEbWCC/DytAWztBdUsDuLT3Tov/QieC";
  // password:123456789
  const newUser = await Users.create({
    username: name,
    password: password,
    isAdmin: true,
  });
});
router.get("/deleteuser", async (req, res) => {
  try {
    // Delete all users
    const result = await Users.deleteMany({});

    if (result.deletedCount === 0) {
      console.log("No users to delete");
      res.send("No users to delete");
    } else {
      res.send(`${result.deletedCount} users deleted`);
    }
  } catch (err) {
    console.error("Error deleting users:", err);
    res.status(500).send("Error deleting users");
  }
});
router.post("/deleteuserbyid", async (req, res) => {
  try {
    const { id } = req.body;

    // Validate the ID
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid or missing user ID" });
    }

    // Attempt to delete the user
    const result = await Users.deleteOne({ _id: id });

    if (result.deletedCount === 0) {
      console.log("No user found with the given ID");
      return res
        .status(404)
        .json({ message: "No user found with the given ID" });
    }
    // Send a single response
    res.json({ message: `User with ID ${id} successfully deleted` });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ message: "Error deleting user" });
  }
});
router.get("/deleteProjectBiding", async (req, res) => {
  try {
    // Delete all users
    const result = await Biddingprice.deleteMany({});

    if (result.deletedCount === 0) {
      console.log("No users to delete");
      res.send("No users to delete");
    } else {
      console.log(`${result.deletedCount} users deleted`);
      res.send(`${result.deletedCount} users deleted`);
    }
  } catch (err) {
    console.error("Error deleting users:", err);
    res.status(500).send("Error deleting users");
  }
});

router.get("/admin/changePricing", isAdmin, async (req, res) => {
  const pricing = await Payments.find({});

  res.render("adminPricing", { pricing });
});
router.post("/admin/changePricing", isAdmin, async (req, res) => {
  const paymentData = req.body;
  if (Array.isArray(paymentData.nonIndianYearlyLink)) {
    paymentData.nonIndianYearlyLink =
      paymentData.nonIndianYearlyLink.join(", "); // Convert array to string
  }

  const updatedPayment = await Payments.findOneAndUpdate(
    {}, // Update all documents that match an empty filter (you may want to specify a filter here)
    paymentData, // Update with the data from req.body
    { new: true, upsert: true } // Return the modified document after update, and create a new one if none exists
  );
  let pricing = await Payments.find({});
  let Message = "Updated Successfully!";

  res.render("adminPricing", { pricing, Message });
});

router.get("/getSkills", sessionChecker, async (req, res) => {
  // Retrieve user data
  const id = req.session.user._id; // Update with the correct user ID retrieval mechanism
  const user = await Users.findOne({ _id: id });
  const url = "https://www.freelancer.com/api/projects/0.1/jobs/";

  let accessToken = user.access_token;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "freelancer-oauth-v1": accessToken,
      },
    });

    if (!response.ok) {
      throw new Error("Network response was not ok " + response.statusText);
    }

    const data = await response.json();

    // Transform the data
    const transformedData = data.result.map((item) => ({
      tag: item.name,
      value: item.id.toString(),
    }));

    // Convert the data to a JSON string
    const jsonString = JSON.stringify(transformedData, null, 2);

    // Define the file path
    const filePath = path.join(__dirname, "exported_data.json");

    // Write the JSON string to a file
    fs.writeFile(filePath, jsonString, (err) => {
      if (err) {
        console.error("Error writing file:", err);
        return res.status(500).send("Error writing file");
      }

      console.log("File successfully written");
      console.log("here is data skills: ", dataSkills);
      res.send("File successfully written");
    });
  } catch (error) {
    console.error("There was a problem with the fetch operation:", error);
    res.status(500).send("There was a problem with the fetch operation");
  }
});

router.get("/userSkills", sessionChecker, async (req, res) => {
  let user = await Users.findOne({ id: req.session.user.id });
  // Retrieve the user's access token
  const accessToken = user.access_token;
  let config = {
    method: "get",
    maxBodyLength: Infinity,
    url: "https://freelancer.com/api/users/0.1/self?jobs=true",
    headers: {
      "freelancer-oauth-v1": accessToken,
    },
  };

  axios
    .request(config)
    .then(async (response) => {
      const jobNamesArray = response.data.result.jobs.map((job) => job.name);
      console.log(jobNamesArray);
      // Update user document with skills
      user.skills = jobNamesArray;

      // Save the updated user document
      await user.save();
      res.redirect("/skills");
    })
    .catch((error) => {
      console.log(error);
    });
});
router.get("/projectReviews", sessionChecker, async (req, res) => {
  try {
    let user = await Users.findOne({ id: req.session.user.id });
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Retrieve the user's access token
    const accessToken = user.access_token;
    console.log("Here is access token: ", accessToken);
    const projectIds = [38217462];
    let config = {
      method: "get",
      maxBodyLength: Infinity,
      url: "https://www.freelancer.com/api/projects/0.1/projects/",
      headers: {
        "freelancer-oauth-v1": accessToken,
      },
      params: {
        projects: projectIds,
      },
    };

    try {
      const response = await axios.request(config);
      const reviews = response.data; // Assuming the response data is what you need

      // Use `flatted.stringify` to handle circular references
      const serializedReviews = JSON.stringify(reviews);
      res.status(200).json(serializedReviews);
    } catch (axiosError) {
      console.error(
        "Error fetching project reviews from Freelancer API: ",
        axiosError
      );
      res
        .status(500)
        .send("Error fetching project reviews from Freelancer API");
    }
  } catch (error) {
    console.error("Error finding user: ", error);
    res.status(500).send("Error finding user");
  }
});
router.get("/userReviews", sessionChecker, async (req, res) => {
  try {
    const user = await Users.findOne({ id: req.session.user.id });
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Retrieve the user's access token
    const accessToken = user.access_token;
    // const userId = [182963,74276474]; // Replace with actual user ID you want to fetch details for
    // const response = await axios.get(`https://www.freelancer.com/api/users/0.1/users/`,
    const userId = 182963; // Replace with actual user ID you want to fetch details for
    const response = await axios.get(
      `https://www.freelancer.com/api/users/0.1/users/${userId}/`,
      {
        headers: {
          "freelancer-oauth-v1": accessToken, // Add OAuth access token to headers
        },
        params: {
          users: userId,
          jobs: true,
          reputation: true,
          employer_reputation: true,
          reputation_extra: true,
          employer_reputation_extra: true,
          user_recommendations: true,
          portfolio_details: true,
          preferred_details: true,
          badge_details: true,
          status: true,
          // Include other parameters as needed
        },
      }
    );

    const userData = response.data; // User data retrieved from the API
    res.json(userData); // Send user data as response
  } catch (error) {
    console.error("Error fetching user reviews:", error);
    res.status(500).send("Error fetching user reviews"); // Send error response
  }
});

module.exports = {
  router: router,
  processAutoBids: processAutoBids,
};
