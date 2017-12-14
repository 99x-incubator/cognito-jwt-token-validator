import * as jwt from 'jsonwebtoken';
import * as jwkToPem from 'jwk-to-pem';
import * as request from 'request';

import {JWK, JWT, PemDictionary, PolicyDocument, PolicyStatement, TokenUse} from './models';


export const validateIdToken = async (
    jwtToken: string, pems: PemDictionary, iss: string, aud: string,
    tokenUse: TokenUse) => {
  const decodedJwt = jwt.decode(jwtToken, {complete: true}) as JWT;
  // Fail if the token is not jwt
  if (!decodedJwt) {
    throw new Error('Not a valid JWT Token');
  }

  // Fail if token issure is invalid
  if (decodedJwt.payload.iss !== iss) {
    throw new Error('Invalid issuer: ' + decodedJwt.payload.iss);
  }

  // Fail if token audience is invalid
  if (decodedJwt.payload.aud !== aud) {
    throw new Error('Invalid aud: ' + decodedJwt.payload.aud);
  }

  // Reject the jwt if it's not the expected type of token
  if (!(decodedJwt.payload.token_use === tokenUse)) {
    throw new Error('Invalid token_use: ' + decodedJwt.payload.token_use);
  }

  // Get the kid from the token and retrieve corresponding PEM
  const kid = decodedJwt.header.kid;
  const pem = pems[kid];
  if (!pem) {
    throw new Error('Invalid kid: ' + decodedJwt.header.kid);
  }

  return new Promise((resolve, reject) => {
    jwt.verify(jwtToken, pem, {issuer: iss}, (err, payload) => {
      if (err) {
        switch (err.name) {
          case 'TokenExpiredError':
            reject(new Error('JWT Token Expired.'));
            break;
          case 'JsonWebTokenError':
            reject(new Error('Invalid JWT Token.'));
            break;
          default:
            reject(new Error(
                'Token verification failure. ' + JSON.stringify(err, null, 2)));
            break;
        }
      } else {
        resolve(decodedJwt.payload);
      }
    });
  });
};

export const generateDummyToken = (sub: string) => {
  return jwt.sign({sub}, 'dummyKey');
};

export const decodeToken = (jwtToken: string) => {
  const decodedJwt = jwt.decode(jwtToken, {complete: true}) as JWT;
  if (decodedJwt) return decodedJwt;
  throw new Error('Invalid JWT token');
};

export const getPems = (jwks: JWK[]) => {
  const pems: PemDictionary = {};
  for (let i = 0; i < jwks.length; i++) {
    const keyId = jwks[i].kid;
    const modulus = jwks[i].n;
    const exponent = jwks[i].e;
    const keyType = jwks[i].kty;
    const jwk = {kty: keyType, n: modulus, e: exponent};
    const pem = jwkToPem(jwk);
    pems[keyId] = pem;
  }
  return pems;
};

export const getJWKs = async (jwksPath: string) => {
  return new Promise((resolve, reject) => {
    request({url: jwksPath, json: true}, (error, response, body) => {
      if (error || response.statusCode !== 200) {
        return reject(new Error(
            'Error while getting JWKs. ' + JSON.stringify(error, null, 2)));
      }
      resolve(body['keys']);
    });
  });
};
