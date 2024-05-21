import { aryval, hextoBA, rstrtohex, utf8tohex, ArrayBuffertohex, hextoArrayBuffer, pemtohex, ishex, hextopem } from "typepki-strconv";
import { getASN1, pospad } from "typepki-asn1gen";
import { asn1parse } from "typepki-asn1parse";

// == hash ===========================
/**
 * get hexadecimal hash value of ArrayBuffer with specified hash algorithm
 * @param alg - hash algorithm (ex. "SHA-256")
 * @param ab - ArrayBuffer value to be hashed
 * @return hexadecimal hash value
 * @example
 * await hashab("SHA-256", hextoArrayBuffer("616161")
 * -> ...
 */
export async function hashab(alg: string, ab: ArrayBuffer): Promise<string> {
  return ArrayBuffertohex(await crypto.subtle.digest({name: alg}, ab));
}

/**
 * get hexadecimal hash value of hexadecimal string data with specified hash algorithm
 * @param alg - hash algorithm (ex. "SHA-256")
 * @param hex - hexadecimal string value to be hashed
 * @return hexadecimal hash value
 * @example
 * await hashhex("SHA-256", "616161")
 * -> ...
 */
export async function hashhex(alg: string, hex: string): Promise<string> {
  return await hashab(alg, hextoArrayBuffer(hex));
}

/**
 * get hexadecimal hash value of UTF-8 string with specified hash algorithm
 * @param alg - hash algorithm (ex. "SHA-256")
 * @param u8str - hexadecimal string value to be hashed
 * @return hexadecimal hash value
 * @example
 * await hashutf8("SHA-256", "そらSky")
 * -> ...
 */
export async function hashutf8(alg: string, u8str: string): Promise<string> {
  return await hashhex(alg, utf8tohex(u8str));
}

/**
 * get hexadecimal hash value of raw string with specified hash algorithm
 * @param alg - hash algorithm (ex. "SHA-256")
 * @param rstr - hexadecimal string value to be hashed
 * @return hexadecimal hash value
 * @example
 * await hashrstr("SHA-256", "\0\0\0")
 * -> ...
 */
export async function hashrstr(alg: string, rstr: string): Promise<string> {
  return await hashhex(alg, rstrtohex(rstr));
}

/**
 * sign hexadecimal data with specified private key and algorithm
 * @param alg - signature algorithm name (ex. SHA256withRSA)
 * @param key - private key object
 * @param hData - hexadecimal data to be signed
 * @return hexadecimal signature value
 * @see https://developer.mozilla.org/ja/docs/Web/API/SubtleCrypto/sign
 * @example
 * await signHex("SHA256withECDSA", prvkey, "616161") -> "631b3f..."
 */
export async function signHex(alg: string, key: CryptoKey, hData: string): Promise<string> {
  //console.log(key);
  const keyalgname = key.algorithm.name;
  const u8aData = new Uint8Array(hextoBA(hData));
  let param: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  if (keyalgname == "RSASSA-PKCS1-v1_5") {
    param = { name: keyalgname } as AlgorithmIdentifier;
  } else if (keyalgname == "RSA-PSS") {
    param = { name: keyalgname, saltLength: 32 } as RsaPssParams;
  } else { // if (keyalgname == "ECDSA") 
    param = {
      name: keyalgname,
      namedCurve: "P-256",
      hash: { name: sigAlgToHashAlg(alg) }
    } as EcdsaParams;
  } 
  const abSig = await crypto.subtle.sign(param, key, u8aData);
  return ArrayBuffertohex(abSig);
}

/**
 * verify signature with specified public key, algorithm and data
 * @param alg - signature algorithm name (ex. SHA256withRSA)
 * @param key - public key object
 * @param hSig - hexadecimal signature value
 * @param hData - hexadecimal data to be verified
 * @param sigopt - salt length for RSA-PSS or curve name for ECDSA
 * @return true if signature is valid
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
 * @example
 * await verifyHex("SHA256withECDSA", pubkey, "91ac...", "616161") -> true
 */
export async function verifyHex(alg: string, key: CryptoKey, hSig: string, hData: string, sigopt?: number | string): Promise<boolean> {
  const keyalgname = key.algorithm.name;
  let param: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  if (keyalgname == "RSASSA-PKCS1-v1_5") {
    param = { name: keyalgname } as AlgorithmIdentifier;
  } else if (keyalgname == "RSA-PSS") {
    let len;
    if (sigopt == undefined) {
      len = getDefaultSaltLength(alg);
    } else {
      len = sigopt;
    }
    param = { name: keyalgname, saltLength: len } as RsaPssParams; // , saltLength: 32
  } else { // keyalgname == "ECDSA"
    param = {
      name: keyalgname,
      namedCurve: sigopt,
      hash: sigAlgToHashAlg(alg)
    } as EcdsaParams;
  } 
  const u8aSig = new Uint8Array(hextoBA(hSig));
  const u8aData = new Uint8Array(hextoBA(hData));
  return await crypto.subtle.verify(param, key, u8aSig, u8aData);
}

function getDefaultSaltLength(alg: string) {
  switch (alg) {
    case "SHA1withRSAandMGF1":
      return 20;
    case "SHA256withRSAandMGF1":
      return 32;
    case "SHA384withRSAandMGF1":
      return 48;
    case "SHA512withRSAandMGF1":
      return 64;
    default:
      throw new Error(`salt not supported for: ${alg}`);
  }
}

// == import PEM private/public key ===========================
/**
 * import key from PEM private/public key string
 * @param pem - PEM PKCS#8 private key or public key string
 * @param alg - signature algorithm (SHA{1,224,256,384,512}with{RSA,RSAandMGF1,ECDSA})
 * @return CryptoKey object of W3C Web Crypto API
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
 * @description
 * This function import a CryptoKey object from PEM key file.
 * @example
 * let key = await importPEM("-----BEGIN PRIVATE...", "SHA256withRSA");
 */
export async function importPEM(pem: string, alg: string, sigopt?: number | string): Promise<CryptoKey> {
  const pemab: ArrayBuffer = hextoArrayBuffer(pemtohex(pem));
  const format: "pkcs8" | "spki" = getImportFormat(pem);
  if (format == "pkcs8") {
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pemab,
      getImportAlgorithm(pem, alg, sigopt),
      true,
      ["sign"]
    );
    return key;  
  } else { // "spki"
    const key = await crypto.subtle.importKey(
      "spki",
      pemab,
      getImportAlgorithm(pem, alg, sigopt),
      true,
      ["verify"]
    );
    return key;  
  }
}

function getImportAlgorithm(pem: string, alg: string, sigopt?: number | string): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
  const matchResult = alg.match(/^SHA(1|224|256|384|512)with(RSA|RSAandMGF1|ECDSA)$/);
  if (matchResult == null) {
    throw new Error(`algorithm not supported: ${alg}`);
  }

  if (matchResult[2] == "RSA") {
    return {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-" + matchResult[1] }
    } as AlgorithmIdentifier;
  } else if (matchResult[2] == "RSAandMGF1") {
    return {
      name: "RSA-PSS",
      hash: { name: "SHA-" + matchResult[1] }
    } as RsaHashedImportParams;
  } else { // "ECDSA":
    return {
      name: "ECDSA",
      namedCurve: sigopt
    } as EcKeyImportParams;
  }
}

function getImportKeyUsage(pem: string): Array<string> {
  if (pem.indexOf("-BEGIN PRIVATE KEY-") != -1) return ["sign"];
  if (pem.indexOf("-BEGIN PUBLIC KEY-") != -1) return ["verify"];
  throw new Error("keyUsage for importKey in PEM not supported");
}

function getImportFormat(pem: string): "pkcs8" | "spki" {
  if (pem.indexOf("-BEGIN PRIVATE KEY-") != -1) return "pkcs8";
  if (pem.indexOf("-BEGIN PUBLIC KEY-") != -1) return "spki";
  throw new Error("format for importKey in PEM not supported");
}

export function sigAlgToHashAlg(alg: string): string | null {
  const matchResult = alg.match(/^SHA(1|224|256|384|512)with/);
  if (matchResult == null) return null;
  return "SHA-" + matchResult[1];
}

/**
 * convert ECDSA signature value from RS concatinated to ASN.1 encoded
 * @param hRS - hexadecimal string of R and S concatinated signature value
 * @return ASN.1 DER encoded ECDSA signature value
 * @see {@link sigASN1toRS}
 * @description
 * ECDSA signature value has two types of encoding:
 * - R and S value concatinated encoding used in W3C Web Crypto API or JSON Web Signature.
 * - ASN.1 SEQUENCE of INTEGER R and S value used in OpenSSL
 *
 * This function converts a ECDSA signature encoding from 
 * concatinated to ASN.1. This function supports ECDSA signatures by P-256, P-384 and P-521.
 * @example
 * sigRStoASN1("
 *  69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060
 *  76ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f")
 * ->
 * "3044
 *    0220
 *      69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060
 *    0220
 *      76ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f"
 */
export function sigRStoASN1(hRS: string): string {
  const rslen: number = hRS.length / 2;
  if (rslen != 64 && rslen != 96 && rslen != 132 && ! ishex(hRS)) {
    throw new Error(`argument is not EC P-256|384|521 RS concat signature: rslen=${rslen}`);
  }
    
  const hR: string = pospad(hRS.slice(0, rslen));
  const hS: string = pospad(hRS.slice(rslen));
  const json = { t: "seq",  v: [
                 { t: "int", v: hR },
                 { t: "int", v: hS }
               ] };
  const hASN1 = getASN1(json);
  return hASN1;
}

/**
 * convert ECDSA signature value from ASN.1 encoded to RS concatinated
 * @param hASN - hexadecimal string of ECDSA ASN.1 signature value
 * @return R and S concatinated ECDSA signature value
 * @see {@link sigRStoASN1}
 * @description
 * ECDSA signature value has two types of encoding:
 * - R and S value concatinated encoding used in W3C Web Crypto API or JSON Web Signature.
 * - ASN.1 SEQUENCE of INTEGER R and S value used in OpenSSL
 *
 * This function converts a ECDSA signature encoding from 
 * ASN.1 to concatinated. This function supports ECDSA signatures by P-256, P-384 and P-521.
 * @example
 * sigRStoASN1(
 * "3044
 *    0220
 *      69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060
 *    0220
 *      76ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f")
 * ->
 * "69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060
 *  76ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f"
 */
export function sigASN1toRS(hASN: string, alg?: string): string {
  let hR: string;
  let hS: string;
  try {
    const p = asn1parse(hASN);
    if (aryval(p, "t") === "seq" &&
        aryval(p, "v.0.t") === "int" &&
        aryval(p, "v.1.t") === "int") {
      hR = aryval(p, "v.0.v");
      hS = aryval(p, "v.1.v");
    } else {
      throw new Error("malformed");
    }
  } catch (ex) {
    throw new Error("malformed ASN.1 RS signature");
  }
  
  if (hR.match(/^[8-9a-f]/) || hS.match(/^[8-9a-f]/)) {
    throw new Error("negative R nor S not supported");
  }

  if (hR.match(/^00/)) hR = hR.slice(2);
  if (hS.match(/^00/)) hS = hS.slice(2);

  const n = getRSSigLen(hR, hS, alg);
  //console.log("n=", n);
  const zeros = "000000000000000000000000000000";
  hR = `${zeros}${hR}`.slice(- n);
  hS = `${zeros}${hS}`.slice(- n);
  if (hR.length != n || hS.length != n) {
    throw new Error("too many zero padding");
  }

  return `${hR}${hS}`;
}

export function getRSSigLen(hR: string, hS: string, alg?: string) {
  if (alg === "P-256") return 64;
  if (alg === "P-384") return 96;
  if (alg === "p-521") return 132;
  if (alg !== undefined) throw new Error(`alg not supported: ${alg}`);
  const rLen = hR.length;
  const sLen = hS.length;
  if ((96 < rLen && rLen <= 132) || (96 < sLen && sLen <= 132)) return 132;
  if ((64 < rLen && rLen <= 96) || (64 < sLen && sLen <= 96)) return 96;
  return 64;
}

/**
 * generate a secure random hexadecimal string
 * @param nbyte - length of random bytes
 * @return hexadecimal string of generated random bytes
 * @description
 * This function generates a secure random hexadecimal string
 * with specified bytes by [`crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) 
 * which uses a pseudo-random number generator(PRNG) algorithm.
 * @example
 * getSecureRandom(3) -> "f73ad5"
 * getSecureRandom(3) -> "d431c6"
 * getSecureRandom(256) -> "147ac8..." (string length will be 512=256*2)
 */
export function getSecureRandom(nbyte: number): string {
  const ab: ArrayBuffer = new ArrayBuffer(nbyte);
  const u8a: Uint8Array = new Uint8Array(ab);
  crypto.getRandomValues(u8a);
  return ArrayBuffertohex(ab);
}

/**
 * generate new HMAC key with specified HMAC algorithm
 * @param alg - HMAC algorithm ("hmacSHA{1,256,384,512}")
 * @return hexadecimal string of HMAC key
 * @description
 * This function generates a HMAC key with specified HMAC
 * algorithm with crypto.getRandomValues not
 * crypto.subtle.generateKey. Its byte length will be
 * the same as generateKey as following:
 *
 * - hmacSHA1, hmacSHA256: 64 bytes
 * - hmacSHA384, hmacSHA512: 128 bytes
 *
 * @example
 * getNewHMACKey("hmacSHA256") -> "8ab134..." (64 bytes)
 * getNewHMACKey("hmacSHA512") -> "374cdf..." (128 bytes)
 */
export function getNewHMACKey(alg: string): string {
  const match = alg.match(/^hmacSHA(1|256|384|512)$/);
  if (match == null) {
    throw new Error(`unsupported algorithm: ${alg}`);
  }
  const hashlen = match[1];
  if (hashlen == "1" || hashlen == "256") return getSecureRandom(64);
  return getSecureRandom(128); // for SHA-384 or SHA-512
}

/**
 * get HMAC key object
 * @param alg - HMAC algorithm name ("hmacSHA{1,256,384,512}")
 * @param hKey - hexadecimal string of HMAC key
 * @return HMAC key object
 * @description
 * This function generates CryptoKey object with specified
 * HMAC algorithm and a hexadecimal string of HMAC key value.
 * @see getNewHMACKey
 * @example
 * await getHMACKey("hmacSHA256", "3b6839...") -> CryptoKey object
 */
export async function getHMACKey(alg: string, hKey: string): Promise<CryptoKey> {
  if (! ishex(hKey)) throw new Error("hKey is not a hexadecimal");
  const match = alg.match(/^hmacSHA(1|256|384|512)$/);
  if (match == null) throw new Error(`HMAC alg not supported: ${alg}`);

  const key = await crypto.subtle.importKey(
    "raw",
    hextoArrayBuffer(hKey),
    { name: "HMAC", hash: { name: `SHA-${match[1]}` } },
    true,
    ["sign", "verify"]
  );
  return key;  
}

/**
 * sign hexadecimal data with HMAC
 * @param alg - HMAC algorithm name ("hmacSHA{1,256,384,512}")
 * @param key - CryptoKey object or hexadecimal string of HMAC key
 * @param hData - hexadecimal string data to be signed
 * @return hexadecimal string of HMAC signature
 * @see {@link verifyHMACHex}
 * @example
 * await signHMAXHex("hmacSHA256", "9abf1245...", "616161") -> "7c8ffa..."
 */
export async function signHMACHex(alg: string, key: string | CryptoKey, hData: string): Promise<string> {
  const keyobj: CryptoKey
    = (typeof key == "object") ? key : await getHMACKey(alg, key as string);
  const sigab: ArrayBuffer = await crypto.subtle.sign(
    "HMAC",
    keyobj,
    hextoArrayBuffer(hData)
  );
  return ArrayBuffertohex(sigab);
}

/**
 * verify HMAC signature
 * @param alg - HMAC algorithm name ("hmacSHA{1,256,384,512}")
 * @param key - CryptoKey object or hexadecimal string of HMAC key
 * @param hSig - hexadecimal string of HMAC signature value
 * @param hData - hexadecimal string of data to be verified
 * @return true if the signature is valid
 * @see {@link signHMACHex}
 * @example
 * await verifyHMACHex("hmacSHA256", "9abf1245...", "7ff2bc...", "616161") -> true
 */
export async function verifyHMACHex(alg: string, key: string | CryptoKey, hSig: string, hData: string): Promise<boolean> {
  const keyobj: CryptoKey
    = (typeof key == "object") ? key : await getHMACKey(alg, key as string);
  const result = await crypto.subtle.verify(
    "HMAC",
    keyobj,
    hextoArrayBuffer(hSig),
    hextoArrayBuffer(hData)
  );
  return result;
}

/**
 * generate keypair as PEM keys
 * @param alg - key algorithm (RSA or EC)
 * @param opt1 - RSA key length or EC curve name (P-{256,384,512}) RSA key length default is 2048 and EC curve name default is "P-256"
 * @param opt2 - RSA public exponent as hexadecimal string. The default is "010001" (i.e. 65537)
 * @return Array of private key PEM and public key PEM
 * @see {@link generateKeypairJWK}
 * @description
 * This function generates a RFC 7517 JSON Web Key (JWK) RSA
 * or EC key pair by W3C Web Crypto API.
 * @example
 * await generateKeyPairPEM("RSA") ->
 * ["-----BEGIN PRIVATE...", "-----BEGIN PUBLIC..."] // RSA 2048bit and "010001" public exponent
 * await generateKeyPairPEM("RSA", 4096, "0101") ->
 * ["-----BEGIN PRIVATE...", "-----BEGIN PUBLIC..."] // RSA 4096bit and "0101" public exponent
 * await generateKeyPairPEM("EC") ->
 * ["-----BEGIN PRIVATE...", "-----BEGIN PUBLIC..."] // P-256 as default
 * await generateKeyPairPEM("EC", "P-521") ->
 * ["-----BEGIN PRIVATE...", "-----BEGIN PUBLIC..."] // P-521
 */
export async function generateKeypairPEM(alg: "RSA" | "EC", opt1?: string | number, opt2?: string): Promise<string[]> {
  const kp: CryptoKeyPair = await generateKeypairObj(alg, opt1, opt2) as CryptoKeyPair;
  //console.log(kp); 
  const prvab = await crypto.subtle.exportKey("pkcs8", kp.privateKey as CryptoKey);
  const pubab = await crypto.subtle.exportKey("spki", kp.publicKey as CryptoKey);
  const prvpem = hextopem(ArrayBuffertohex(prvab), "PRIVATE KEY", "\n");
  const pubpem = hextopem(ArrayBuffertohex(pubab), "PUBLIC KEY", "\n");
  const result: Array<string> = [prvpem, pubpem];
  //console.log(result);
  return result;
}

/**
 * generate keypair as JWK keys
 * @param alg - key algorithm (RSA or EC)
 * @param opt1 - RSA key length or EC curve name (P-{256,384,512}) RSA key length default is 2048 and EC curve name default is "P-256"
 * @param opt2 - RSA public exponent as hexadecimal string. The default is "010001" (i.e. 65537)
 * @return Array of private key JWK and public key JWK.
 * @see {@link generateKeypairPEM}
 * @see https://www.rfc-editor.org/rfc/rfc7517
 * @description
 * This function generates a RFC 7517 JSON Web Key (JWK) RSA
 * or EC key pair by W3C Web Crypto API.
 * @example
 * await generateKeyPairJWK("EC") -> [{
 *   kty: "EC",
 *   crv: "P-256"
 *   d: "..."
 *   ...
 * },{
 *   kty: "EC",
 *   crv: "P-256"
 *   x: "...",
 *   y: "...",
 * }]
 */
export async function generateKeypairJWK(alg: "RSA" | "EC", opt1?: string | number, opt2?: string): Promise<object[]> {
  const kp: CryptoKeyPair = await generateKeypairObj(alg, opt1, opt2) as CryptoKeyPair;
  const prvjwk = await crypto.subtle.exportKey("jwk", kp.privateKey as CryptoKey);
  const pubjwk = await crypto.subtle.exportKey("jwk", kp.publicKey as CryptoKey);
  delete prvjwk.alg;
  delete prvjwk.ext;
  delete prvjwk.key_ops;
  delete pubjwk.alg;
  delete pubjwk.ext;
  delete pubjwk.key_ops;
  const result = [prvjwk, pubjwk];
  //console.log(result);
  return result;
}

async function generateKeypairObj(alg: "RSA" | "EC", opt1?: string | number, opt2?: string): Promise<CryptoKeyPair> {
  let kp: CryptoKeyPair;
  if (alg == "RSA") {
    const keylen = (opt1 !== undefined) ? opt1 : 2048;
    const pubexpHex = (opt2 !== undefined) ? opt2 : "010001";
    const pubexpU8a = new Uint8Array(hextoArrayBuffer(pubexpHex));
    kp = await crypto.subtle.generateKey(
      {
        "name": "RSASSA-PKCS1-v1_5",
        "modulusLength": keylen,
        "publicExponent": pubexpU8a,
        "hash": "SHA-256"
      } as RsaHashedKeyGenParams,
      true,
      ["sign", "verify"]
    );
  } else if (alg == "EC") {
    const curve = (opt1 !== undefined) ? opt1 : "P-256";
    kp = await crypto.subtle.generateKey(
      {
        "name": "ECDSA",
        "namedCurve": opt1
      } as EcKeyGenParams,
      true,
      ["sign", "verify"]
    );
  } else {
    throw new Error("error");
  }
  return kp;
}

/*
256 col64
69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060
76ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f
384 col96
cb6c3115a81bfb7581df9bd05e4116ed90f483fdbe03c8c8204c6d2a9bba7520580dfb86f5649ad2de5fce59b67b4b61
59924fcd38c995d782d33f1750134cbef6e609558fa6d7e6a0eff7d32b90a48df5eb9fed839fa492cb9da50a017a0f12
521 col132
014e8d5d7ea8494a0b4e48372b76e61bee7fdd0db7463aee4551e9b7df15f8a9d6216c478b046406450d8b0cbb97098b126ac6362800384d726aa230c579092e7e3b
01e01a525804b4095d5cd57c2ca031dab907c2d08dc792b93261ec2e656058a86d2479cea115b26bc69e3e6894b0a9dcd0d8f65aa6a69f499a02980bd3c8ca352af4
 */
