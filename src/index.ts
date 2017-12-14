import * as Logger from 'debug';

import {JWK, PemDictionary, TokenUse} from './models';
import {decodeToken, generateDummyToken, getJWKs, getPems, validateIdToken} from './utils';

const debug = Logger('cognito-jwt-token-validator');

export class Validator {
  private pems: PemDictionary;

  /**
   *
   * @param iss Issuer
   * @param aud Audience
   * @param tokenUse Type of token expected. 'id' or 'access'
   * @param fakeAuth Set this to true this when you don't want to validate the
   * JWT token. Default: false
   *
   */
  constructor(
      private iss: string, private aud: string,
      private tokenUse: TokenUse = TokenUse.ID, private fakeAuth = false) {}

  /**
   *
   * @param token JWT Token. Can be empty or anything if running in fakeAuth
   * mode
   * @throws Upon unsuccessful validation of token
   * @returns Decoded payload data of the JWT token upon successful validation
   */
  async validate(token?: string) {
    let tokenPayload: {} = {sub: 'Dummy'};

    if (this.fakeAuth) {
      debug('Running in fake Authorization mode.');
      if (token) tokenPayload = token;
    } else {
      if (!token) throw new Error('No token provided');
      if (!this.pems) {
        debug('JWKs arent cached. Obtaining JWKs.');
        const jwksUrl = await getJWKs(`${this.iss}/.well-known/jwks.json`);
        this.pems = getPems(jwksUrl as JWK[]);
        debug('PEMs generated from JWKs.');
      }
      tokenPayload = await validateIdToken(
          token, this.pems, this.iss, this.aud, this.tokenUse);
    }
    debug('JWT token validated.');
    return tokenPayload;
  }
}

export {TokenUse};
