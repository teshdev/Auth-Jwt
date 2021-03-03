const router = require('express').Router();
const User = require('../model/User');
const jwt = require('jsonwebtoken')

//validation
const Joi = require('@hapi/joi');
var bcrypt = require('bcryptjs');

const schema = Joi.object().keys({
    name: Joi.string().min(6),
    email: Joi.string().min(6).required().email(),
    password: Joi.string().min(6).required(),
});
router.post('/register', async (req, res) => {
    //Validating data before saving inot db
    Joi.assert(req.body, schema, (err, value) => {
        if (err) {
            res.send(err.details);
        } else {
            console.log(value)
        }
    });
    //Checking if user is already in databse
    const emailExist = await User.findOne({ email: req.body.email });
    if (emailExist) return res.status(400).send("Email already used!");
    //Hash The Password
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = await bcrypt.hashSync(req.body.password, salt);
    // Creating new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });
    try {
        const savedUser = await user.save();
        res.send(savedUser);
    } catch (err) {
        res.status(400).send(err);
    }
});
//Login
router.post('/login', async (req, res) => {
    //Ckecking if eamil exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send("Email doen't exist!");
    //Password is correct
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid password');
    //Create a token
    const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
    res.header('auth-token', token).send(token);
})

module.exports = router;