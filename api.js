const express = require("express");
const api = express();
const db = require("./db/models");
const users = require('./controllers/users');

api.use(express.json());
api.use('/', users);

api.listen(3440, () => {
    console.log("teste: http://localhost:3440");
});