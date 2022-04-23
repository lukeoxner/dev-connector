const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const normalize = require('normalize');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
	'/',
	[
		check('name', 'Name is required').not().isEmpty(),
		check('email', 'Please include a valid email').not().isEmpty(),
		check(
			'password',
			'Please enter a password with 6 or more characters'
		).isLength({ min: 6 }),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			// See if user already exists
			let user = await User.findOne({ email: email });
			// If user already exists, send error
			if (user) {
				return res.status(400).json({
					errors: [{ msg: 'User already exists' }],
				});
			}

			// Get user gravatar
			const avatar = normalize(
				gravatar.url(email, {
					s: '200',
					r: 'pg',
					d: 'mm',
				}),
				{ forceHttps: true }
			);

			// Create new user (does NOT save to database)
			user = new User({
				name,
				email,
				avatar,
				password,
			});

			// Encrypt password using bcrypt
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);

			// Save user to database, returns promise
			// Anything that returns a promise needs await in front
			await user.save();

			// Return JsonWebToken
			const payload = {
				user: {
					id: user.id,
				},
			};

			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{ expiresIn: 360000 },
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.log(err.message);
			res.status(500).send('Server error');
		}
	}
);

module.exports = router;
