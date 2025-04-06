const express = require('express');
const createError = require('http-errors');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');
const bodyParser = require('body-parser');
const flash = require('connect-flash');
const cron = require('node-cron');
const axios = require('axios');
const database = require('./config/database');
const cors = require('cors'); // Import cors middleware

const indexRouter = require('./routes/index');
const { processAutoBids } = indexRouter; // Destructure processAutoBids from indexRouter
const usersRouter = require('./routes/users');

require('dotenv').config();

const app = express();

database.connect();
app.use(cors({ origin: "*" }));
// Parse JSON bodies
app.use(bodyParser.json());

// Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files
app.use(express.static('public'));

// Session middleware
app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Flash messages middleware
app.use(flash());

// Middleware to expose flash messages to views
app.use((req, res, next) => {
  res.locals.messages = req.flash();
  next();
});

// View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Logger middleware
app.use(logger('dev'));

// Parse incoming requests with JSON payloads
app.use(express.json());

// Parse incoming requests with URL-encoded payloads
app.use(express.urlencoded({ extended: false }));

// Parse cookies
app.use(cookieParser());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
// Mount routers
app.use('/', indexRouter.router); // Use router from indexRouter
app.use('/users', usersRouter);

// Catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// Set up cron job
cron.schedule('* * * * *', async () => {
  console.log('Running a task every minute');

  try {
    const responseData = await processAutoBids();
    console.log('Response from processAutoBids:', responseData);
  } catch (error) {
    console.error('Error occurred while running processAutoBids:', error);
  }
});

// Error handler
app.use(function(err, req, res, next) {
  // Set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // Render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;