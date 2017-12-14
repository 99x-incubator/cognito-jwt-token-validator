# Cognito-JWT-Token-Validator

 Cognito JWT Token Validator provides an easy solution to validate JWT ID tokens provided by Cognito IdP, that is to be used in a custom authorizer. 

## Features

* Automatic handling of JWKs
* Verification of JWT with the issuer, audience, token_use, and expiry

## Installation

```bash
npm install cognito-jwt-token-validator --save
```

## Usage

Typesrcipt:
```javascript
import { Validator } from 'cognito-jwt-token-validator';

// Authorize function

const validator = new Validator('issuer', 'audience');
const authorize = async (token) => {
	try {
    	const payload = await validator.validate(token);
    	return {
    		userid: payload.sub
    	};
    } catch(err) {
    	console.log('Failed to validate the token');
        return {
        	failed: true
        }
    }
};

```


Javascript (with promises): 
```javascript
const validator = require('cognito-jwt-token-validator').Validator('iss', 'aud'); 

// Authorize function
const authorize = function (token) {
	return validator.validate(token)
    	.then((payload) => {
        	return { userid: payload.sub };
        });
};

```

## Contributing