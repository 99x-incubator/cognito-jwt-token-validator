import { Validator } from '../build/src/index';

const validator = new Validator(process.env.iss, process.env.aud, false);

export const authorize = async (event, context, cb) => {
  const token = event.authorizationToken;

  if (!token) {
    return cb('Missing authorization token');
  }

  try {
    const {sub} = await validator.validate(token);

    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'allow',
          Resource: '*'
        }
      ]
    };

    const response = {
      principalId: sub,
      policyDocument
    };

    console.log('Authorization successful. Sending policy document: ');
    console.log(JSON.stringify(response, null, 2));
    cb(null, response);
  } catch (err) {
    console.log('An error occurred while authorizing: ');
    console.log(err);
    cb(err);
  }
};

export const hello = (event, context, cb) => {
  const response = {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Go Serverless Webpack (Typescript) v1.0! Your function executed successfully!',
      input: event,
    }),
  };

  cb(null, response);
}
