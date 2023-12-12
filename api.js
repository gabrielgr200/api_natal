const express = require("express");
const cors = require('cors');
const api = express();
const db = require("./db/models");
const users = require('./controllers/users');

api.use(express.json());
api.use('/', users);


api.use(cors({
    origin: 'http://127.0.0.1:5500', // Substitua pelo domínio correto do seu frontend
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: 'Content-Type,Authorization',
}));


api.listen(3440, () => {
    console.log("teste: http://localhost:3440");
});