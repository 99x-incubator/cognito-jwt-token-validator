import * as Logger from 'debug';

import {JWK, PemDictionary} from './models';
import {getJWKs, getPems, validateIdToken} from './utils';

const debug = Logger('cognito-jwt-token-validator');

export class Validator {
  private pems?: PemDictionary;

  /**
   *
   * @param iss Issuer
   * @param aud Audience
   * @param fakeAuth Set this to true this when you don't want to validate the
   * JWT token. Default: false
   *
   */
  constructor(
      private iss: string, private aud: string, private token_use: string, private fakeAuth = false) {}

  /**
   *
   * @param token JWT Token. Can be empty or anything if running in fakeAuth
   * mode
   * @throws Upon unsuccessful validation of token
   * @returns Decoded payload data of the JWT token upon successful validation.
   */
  async validate(token?: string) {
    let tokenPayload: {[key: string]: string} = {sub: 'Dummy'};

    if (this.fakeAuth) {
      debug('Running in fake Authorization mode.');
      if (token) tokenPayload.token = token;
    } else {
      if (!token) throw new Error('No token provided');
      if (!this.pems) {
        debug('JWKs arent cached. Obtaining JWKs.');
        const jwksUrl = await getJWKs(`${this.iss}/.well-known/jwks.json`);
        this.pems = getPems(jwksUrl as JWK[]);
        debug('PEMs generated from JWKs.');
      }
      tokenPayload =
          await validateIdToken(token, this.pems, this.iss, this.aud, this.token_use);
    }

    debug('JWT token validated.');
    return tokenPayload;
  }
}
