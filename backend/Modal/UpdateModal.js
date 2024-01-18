// const { DataTypes } = require('sequelize');
// const { v4: uuidv4 } = require('uuid');
// const sequelize = require('../Sequelize');  // Assuming you have a Sequelize instance

// const Update = sequelize.define('Update', {
//   id: {
//     type: DataTypes.UUID,
//     defaultValue: uuidv4,
//     allowNull: false,
//     primaryKey: true,
//   },
//   topic: {
//     type: DataTypes.STRING,
//     allowNull: false,
//   },
//   desc: {
//     type: DataTypes.JSON, // Change the type to JSON for an object
//     allowNull: false,
//   },
//   uploadDate: {
//     type: DataTypes.STRING,
//     defaultValue: () => new Date().toLocaleDateString(),
//   },
//   time: {
//     type: DataTypes.STRING,
//     defaultValue: () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
//   },
// }, {
//   tableName: 'updates', // Set the table name explicitly
// });

// // Synchronize the model with the database (create the table)
// Update.sync({ force: false })
//   .then(() => {
//     console.log('Updates Table created');
//   })
//   .catch((err) => {
//     console.error('Error creating table:', err);
//   });

// module.exports = Update;

const { DataTypes } = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const sequelize = require('../Sequelize');  // Assuming you have a Sequelize instance

const Update = sequelize.define('Update', {
  id: {
    type: DataTypes.UUID,
    defaultValue: uuidv4,
    allowNull: false,
    primaryKey: true,
  },
  topic: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  desc: {
    type: DataTypes.JSON, // Change the type to JSON for an object
    allowNull: false,
  },
  uploadDateTime: {
    type: DataTypes.DATE,
    defaultValue: () => new Date(),
  },
}, {
  tableName: 'updates', // Set the table name explicitly
});

// Synchronize the model with the database (create the table)
Update.sync({ force: false })
  .then(() => {
    console.log('Updates Table created');
  })
  .catch((err) => {
    console.error('Error creating table:', err);
  });

module.exports = Update;
