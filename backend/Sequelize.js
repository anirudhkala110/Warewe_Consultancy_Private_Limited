// Sequelize.js
const { Sequelize } = require('sequelize');
const doenv = require('dotenv')

doenv.config()

const sequelize = new Sequelize({
  dialect: 'mysql', // Change this to 'mysql' instead of 'mysql2'
  host: process.env.HOST,
  username: process.env.USER,
  password: process.env.PASS,
  database: process.env.DATABASE,
  logging: false,
});

module.exports = sequelize;
