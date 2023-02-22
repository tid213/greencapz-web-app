var express = require('express');
var router = express.Router();

var user_controller = require('../controllers/userController');
var readings_controller = require('../controllers/readingsController');

// GET user home page.
router.get('/', user_controller.index);

// Create User GET and POST
router.get('/signup', user_controller.user_create_get);
router.post('/signup', user_controller.user_create_post);

//User login GET
router.get('/login', user_controller.user_login);

// User login POST
router.post('/login', user_controller.user_login_post);

//User logout
router.get('/logout', user_controller.user_logout);

//About page
router.get('/about', user_controller.about_page_get);

// Email Validation confirmation/resend POST
router.get('/confirmation/:token', user_controller.confirmationPost);
router.post('/resend', user_controller.resendTokenPost);

router.get('/dashboard', user_controller.user_dashboard);

// Password change
router.get('/changepassword', user_controller.password_change_get);
router.post('/changepassword', user_controller.password_change_post);

// Delete User GET and POST
router.get('/delete', user_controller.user_delete_get);
router.post('/delete', user_controller.user_delete_post);
router.get('/delete/:token', user_controller.user_delete_confirmation);

// Update user GEt and POST
router.get('/update', user_controller.user_update_get);
router.post('/update', user_controller.user_update_post);

//Forgot password
router.get('/forgotpassword', user_controller.forgot_password_get);
router.post('/forgotpassword', user_controller.forgot_password_post);
router.get('/resetpassword/:token', user_controller.reset_password_get);
router.post('/resetpassword/:token', user_controller.reset_password_post);

//Add Reading
router.get('/addreading', user_controller.add_reading_get);
router.post('/addreading', user_controller.add_reading_post);

module.exports = router;
