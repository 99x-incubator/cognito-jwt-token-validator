export interface PolicyMap { [key: string]: PolicyStatement[]; }

export interface PolicyDocument {
  Version: string;
  Statement: PolicyStatement[];
}

export interface PolicyStatement {
  Action?: string;
  Effect?: string;
  Resource?: string;
}

export interface JWT {
  header: {[key: string]: string};
  payload: {[key: string]: string};
  signature: {[key: string]: string};
}

export interface JWK {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

export interface PemDictionary { [key: string]: string|Buffer; }
