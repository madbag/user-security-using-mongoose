const { Router } = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const mongoose = require('mongoose');
const User = require('../models/User.model');

router.get('/signup', (req, res) => 
res.render('auth/signup'));

router.post('/signup', (req,res,next) => {
    //console.log('The form data: ', req.body);
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.'});
        return;
    }

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res
        .status(500)
        .render('auth/signup', {errorMessage: 'Password needs to have at least 6 chars and must contain atleast one number, one lowercase and one uppercase letter.'});
        return;
    }
    
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
        //console.log(`password hash: ${hashedPassword}`);
        return User.create({
            username, 
            email,
            passwordHash: hashedPassword
        });
    })
    .then(userFromDB => {
        //console.log('Newly created user is: ', userFromDB)
        res.redirect('/userProfile');
    })
    .catch(error => {
        if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render('auth/signup', {errorMessage: error.message});
        } else if (error.code === 11000){
            console.log("Username and email need to be unique. Either username or email is already used.");

            res.status(500).render('auth/signup', {
                errorMessage: 'User not found and/or incorrect password.'
            })
        } else {
            next(error);
        }
    });
});

router.get('/login', (req, res) => res.render('auth/login'));

router.post('/login', (req, res, next) => {
    console.log('SESSION =======>', req.session);

    const { email, password } = req.body;
    if (email === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'Please enter both, email and password to login.'
        });
        return;
    }

    User.findOne({email})
    .then(user => {
        if (!user) {
            console.log("Email not registered.");
            res.render('auth/login', { errorMessage : 'User not found and/or incorrect password.'});
            return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) {
           //res.render('users/user-profile', { user });

           req.session.currentUser = user;
           res.redirect('/userProfile');
        } else {
            console.log("Incorrect password.");
            res.render('auth/login', { errorMessage: 'User not found and/or incorrect password'})
        }
    })
    .catch(error => next(error))
})

router.get('/userProfile', (req,res) => 
res.render('users/user-profile', { userInSession: req.session.currentUser }));

router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
        if(err)next(err);
        res.redirect('/');
    });
});

module.exports = router;