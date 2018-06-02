const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const routes = require('./routes');
const { Logger } = require('./lib');
const { initSuperAdmin } = require('./lib/db-initializer');

const app = express();
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    initSuperAdmin();
    app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      next();
    });
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(bodyParser.json());
    app.use('/', routes);
  })
  .catch((err) => {
    Logger.error(err);
    process.exit(1);
  });

module.exports = app;
