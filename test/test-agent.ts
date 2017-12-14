process.env.DEBUG = 'cognito-jwt-token-validator';

import * as readline from 'readline';
import {Validator} from '../src';


async function testToken(iss: string, aud: string, rl: readline.ReadLine) {
  return new Promise<string>(resolve => {
           rl.question('Token: ', (token) => {
             resolve(token);
           });
         })
      .then((token) => {
        const validator = new Validator(iss, aud);
        return validator.validate(token);
      });
}



const rl = readline.createInterface(process.stdin, process.stdout);

rl.question('Issuer: ', (iss) => {
  rl.question('Audience: ', (aud) => {
    testToken(iss, aud, rl)
        .then((res) => console.log(res))
        .then(() => rl.close())
        .catch((err) => console.log(err));
  });
});
