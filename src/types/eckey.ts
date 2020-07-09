export interface KeyJWK {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  ext?: boolean;
}

export interface PublicKeyJWK extends KeyJWK {}

export interface PrivateKeyJWK extends KeyJWK {
  d: string;
}
