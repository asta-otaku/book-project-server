const bcrypt = require("bcrypt");
const SALT_ROUNDS = 10;

// function to generate and return hashed password
const generatePassword = (password) => {
  return bcrypt.hashSync(password, SALT_ROUNDS);
};

const validatePassword = (passwordFromRequest, passwordFromDB) => {
  const isValidPassword = bcrypt.compareSync(
    passwordFromRequest,
    passwordFromDB
  );
  return isValidPassword;
};

module.exports = { generatePassword, validatePassword };
