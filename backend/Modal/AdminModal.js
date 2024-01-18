// // adminModel.js
// const mongoose = require('mongoose');
// const { v4: uuidv4 } = require('uuid'); // Import the uuid function

// const adminSchema = new mongoose.Schema({
//     id: {
//         type: String,
//         default: uuidv4, // Use uuidv4 to generate a random ID
//     },
//     name: {
//         type: String,
//         required: true,
//     },
//     email: {
//         type: String,
//         required: true,
//         unique: true,
//         // You might want to add validation for a valid email address here
//     },
//     password: {
//         type: String,
//         required: true,
//         // You might want to add more validation for password strength here
//     },
// });

// const Admin = mongoose.model('Admin', adminSchema);

// module.exports = Admin;

const { DataTypes } = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const sequelize = require('../Sequelize'); // Import your Sequelize instance

const Admin = sequelize.define('Admin', {
    id: {
        type: DataTypes.UUID,
        defaultValue: () => uuidv4(),
        allowNull: false,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        // You might want to add validation for a valid email address here
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
        // You might want to add more validation for password strength here
    },
});

// console.log('Admin Table')

sequelize.sync({ force: false }) // This will create the table if it doesn't exist and if exists then delete the old one and then create
    .then(() => {
        console.log('\nAdmin Table synchronized\n');
    })
    .catch(error => {
        console.error('\nError synchronizing tables:', error, "\n\n");
    });

module.exports = Admin;
