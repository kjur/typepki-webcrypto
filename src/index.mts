import { aryval, hextoBA, rstrtohex, utf8tohex, ArrayBuffertohex, hextoArrayBuffer, pemtohex, ishex, hextopem } from "typepki-strconv";
import { getASN1, pospad } from "typepki-asn1gen";
import { asn1parse, dig, asn1oidcanon } from "typepki-asn1parse";

export type SignatureAlgorithmName = 
  "hmacSHA1" | "hmacSHA256" | "hmacSHA384" | "hmacSHA512" |
  "SHA1withRSA" | "SHA256withRSA" | "SHA384withRSA" | "SHA512withRSA" |
  "SHA1withECDSA" | "SHA256withECDSA" | "SHA384withECDSA" | "SHA512withECDSA" |
  "SHA1withRSAandMGF1" | "SHA256withRSAandMGF1" | "SHA384withRSAandMGF1" | "SHA512withRSAandMGF1";

// == hash ===========================
/**
 * get hexadecimal hash value of ArrayBuffer with specified hash algorithm
 * @param alg - hash algorithm (ex. "SHA-256")
 * @param ab - ArrayBuffer value to be hashed
 * @return hexadecimal hash value
 * @example
 * await hashab("SHA-256", hextoArrayBuffer("616161"))
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
 * @param sigalg - signature algorithm name (ex. SHA256withRSA)
 * @param keyobjOrString - key for signing. CryptoKey object, PKCS#8 PEM private key or HMAC hexadecimal key string
 * @param hData - hexadecimal data to be signed
 * @param saltlen - RSA-PSS salt length when you don't want to use default length
 * @return hexadecimal signature value
 * @see https://developer.mozilla.org/ja/docs/Web/API/SubtleCrypto/sign
 * @see {@link signBuf}
 *
 * @example
 * await signHex("SHA256withECDSA", prvkeyObj, "616161") -> "631b3f..."
 */
export async function signHex(
  sigalg: SignatureAlgorithmName,
  keyobjOrString: CryptoKey | string, 
  hData: string,
  saltlen?: number
): Promise<string> {
  const abData = hextoArrayBuffer(hData);
  const abSig = await signBuf(sigalg, keyobjOrString, abData, saltlen);
  return ArrayBuffertohex(abSig);
}

/**
 * sign data with specified private key and algorithm
 * @param sigalg - signature algorithm name (ex. SHA256withRSA)
 * @param keyobjOrString - key for signing. CryptoKey object, PKCS#8 PEM private key or HMAC hexadecimal key string
 * @param bufData - data to be signed
 * @param saltlen - RSA-PSS salt length when you don't want to use default length
 * @return ArrayBuffer signature value
 * @see https://developer.mozilla.org/ja/docs/Web/API/SubtleCrypto/sign
 * @see {@link signHex}
 *
 * @example
 * await signBuf("SHA256withECDSA", prvkeyObj, hextoArrayBuffer("616161")) -> ArrayBuffer...
 */
export async function signBuf(
  sigalg: SignatureAlgorithmName,
  keyobjOrString: CryptoKey | string, 
  bufData: ArrayBuffer | Uint8Array | DataView,
  saltlen?: number
): Promise<ArrayBuffer> {
  let key: CryptoKey;
  if (typeof keyobjOrString === "string") {
    const keystr: string = keyobjOrString;
    if (ishex(keystr) && sigalg.indexOf("hmac") === 0) {
      key = await getHMACKey(sigalg, keystr);
    } else {
      if (keystr.indexOf("-BEGIN PRIVATE KEY") === -1) {
        throw new Error("PKCS#8 PEM private key shall be specified");
      }
      key = await importPEM(keystr, sigalg);
    }
  } else {
    key = keyobjOrString;
  }

  const keyalgname: string = key.algorithm.name;
  let param: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  if (keyalgname == "RSASSA-PKCS1-v1_5") {
    param = { name: keyalgname } as AlgorithmIdentifier;
  } else if (keyalgname == "RSA-PSS") {
    let len;
    if (saltlen == undefined) {
      len = getDefaultSaltLength(sigalg);
    } else {
      len = saltlen;
    }
    param = { name: keyalgname, saltLength: len } as RsaPssParams;
  } else if (keyalgname == "ECDSA") {
    const keyalgobj = key.algorithm as EcKeyImportParams;
    param = {
      name: keyalgname,
      namedCurve: keyalgobj.namedCurve,
      hash: { name: sigAlgToHashAlg(sigalg) }
    } as EcdsaParams;
  } else if (keyalgname == "HMAC") {
    param = { name: "HMAC" } as AlgorithmIdentifier;
  } else {
    throw new Error(`key algorihtm not supported to sign: ${keyalgname}`);
  }

  return await crypto.subtle.sign(param, key, bufData);
}

/**
 * verify signature with specified public key, algorithm and data
 * @param sigalg - signature algorithm name (ex. SHA256withRSA)
 * @param keyobjOrString - key for verification. CryptoKey object, PKCS#8 PEM public key or HMAC hexadecimal key string
 * @param hSig - hexadecimal signature value
 * @param hData - hexadecimal data to be verified
 * @param saltlen - RSA-PSS salt length when you don't want to use default length
 * @return true if signature is valid
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
 * @see {@link verifyBuf}
 *
 * @description
 * NOTE1: Generated ECDSA signature value will be a concatinated signature
 * value of R and S which is compatible to JWS(JSON Web Signatures) or
 * W3C Web Crypto API. However it doesn't with OpenSSL nor Java
 * because OpenSSL or Java's ECDSA signature value is an ASN.1 data of R and S.
 * So you may need to convert signature by {@link sigASN1toRS} function
 * to verify a OpenSSL EC signature.
 * <br/>
 * NOTE2: Regarding to RSA-PSS signature verification, default salt length 
 * depends on hash algorithm. For SHA1withRSAandMGF1, SHA256withRSAandMGF1,
 * SHA384withRSAandMGF1 or SHA512withRSAandMGF1, it will be 20, 32, 48 or
 * 64 respectively.
 *
 * @example
 * await verifyHex("SHA256withECDSA", pubkey, "91ac...", "616161") -> true
 */
export async function verifyHex(
  sigalg: SignatureAlgorithmName,
  keyobjOrString: CryptoKey | string, 
  hSig: string,
  hData: string,
  saltlen?: number
): Promise<boolean> {
  const abSig = hextoArrayBuffer(hSig);
  const abData = hextoArrayBuffer(hData);
  return await verifyBuf(sigalg, keyobjOrString, abSig, abData, saltlen);
}

/**
 * verify signature with specified public key, algorithm and data
 * @param sigalg - signature algorithm name (ex. SHA256withRSA)
 * @param keyobjOrString - key for verification. CryptoKey object, PKCS#8 PEM public key or HMAC hexadecimal key string
 * @param abSig - ArrayBuffer signature value
 * @param abData - ArrayBuffer data to be verified
 * @param saltlen - RSA-PSS salt length when you don't want to use default length
 * @return true if signature is valid
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
 * @see {@link verifyHex}
 *
 * @description
 * NOTE1: Generated ECDSA signature value will be a concatinated signature
 * value of R and S which is compatible to JWS(JSON Web Signatures) or
 * W3C Web Crypto API. However it doesn't with OpenSSL nor Java
 * because OpenSSL or Java's ECDSA signature value is an ASN.1 data of R and S.
 * So you may need to convert signature by {@link sigASN1toRS} function
 * to verify a OpenSSL EC signature.
 * <br/>
 * NOTE2: Regarding to RSA-PSS signature verification, default salt length 
 * depends on hash algorithm. For SHA1withRSAandMGF1, SHA256withRSAandMGF1,
 * SHA384withRSAandMGF1 or SHA512withRSAandMGF1, it will be 20, 32, 48 or
 * 64 respectively.
 *
 * @example
 * await verifyBuf("SHA256withECDSA", pubkey, hextoArrayBuffer("91ac..."), hextoArrayBuffer("616161")) -> true
 */
export async function verifyBuf(
  sigalg: SignatureAlgorithmName,
  keyobjOrString: CryptoKey | string,
  abSig: ArrayBuffer,
  abData: ArrayBuffer,
  saltlen?: number
): Promise<boolean> {
  let key: CryptoKey;
  if (typeof keyobjOrString === "string") {
    const keystr: string = keyobjOrString;
    if (ishex(keystr) && sigalg.indexOf("hmac") === 0) {
      key = await getHMACKey(sigalg, keystr);
    } else {
      if (keystr.indexOf("-BEGIN PUBLIC KEY") === -1) {
        throw new Error("PKCS#8 PEM public key shall be specified");
      }
      key = await importPEM(keystr, sigalg);
    }
  } else {
    key = keyobjOrString;
  }

  const keyalgname = key.algorithm.name;
  let param: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  if (keyalgname == "RSASSA-PKCS1-v1_5") {
    param = { name: keyalgname } as AlgorithmIdentifier;
  } else if (keyalgname == "RSA-PSS") {
    let len;
    if (saltlen == undefined) {
      len = getDefaultSaltLength(sigalg);
    } else {
      len = saltlen;
    }
    param = { name: keyalgname, saltLength: len } as RsaPssParams; // , saltLength: 32
  } else if (keyalgname == "ECDSA") {
    const keyalgobj = key.algorithm as EcKeyImportParams;
    param = {
      name: keyalgname,
      namedCurve: keyalgobj.namedCurve,
      hash: sigAlgToHashAlg(sigalg)
    } as EcdsaParams;
  } else if (keyalgname == "HMAC") {
    param = { name: "HMAC" } as AlgorithmIdentifier;
  } else {
    throw new Error(`key algorihtm not supported to verify: ${keyalgname}`);
  }

  return await crypto.subtle.verify(param, key, abSig, abData);
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
 * @param sigopt - saltLength for RSA-PSS
 * @return CryptoKey object of W3C Web Crypto API
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
 *
 * @description
 * This function import a CryptoKey object from PEM key file.
 * <br/>
 * NOTE: For EC key, namedCurve value will be automatically
 * detected by PEM file. So no need to specify.
 *
 * @example
 * key = await importPEM("-----BEGIN PRIVATE...", "SHA256withRSA");
 * key = await importPEM("-----BEGIN PUBLIC...", "SHA256withECDSA");
 * key = await importPEM("-----BEGIN PRIVATE...", "SHA256withRSAandMGF1");
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
    const curve: string | null = pemtocurve(pem);
    if (curve == null) {
      throw new Error("can't find curve name from PEM string");
    }
    return {
      name: "ECDSA",
      namedCurve: curve,
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
 * - ASN.1 SEQUENCE of INTEGER R and S value used in OpenSSL or Java
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
 * // new lines and specs added to understand their structues
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
 * - ASN.1 SEQUENCE of INTEGER R and S value used in OpenSSL or Java
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
 * // new lines and specs added to understand their structues
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

/**
 * get curve name from PKCS#8 PEM private/public key string
 * @param pem - PKCS#8 PEM private or public key string
 * @return supported EC curve name (P-256/384/521) otherwise returns null
 * @example
 * pemtocurve("-----BEGIN PRIVATE...") -> "P-521"
 * pemtocurve("-----BEGIN PUBLIC...") -> null // if RSA key or not supported curve
 */
export function pemtocurve(pem: string): string | null {
  if (pem.indexOf("-BEGIN PRIVATE KEY-") !== -1) return prvpemtocurve(pem);
  if (pem.indexOf("-BEGIN PUBLIC KEY-") !== -1) return pubpemtocurve(pem);
  return null;
}

function prvpemtocurve(pem: string): string | null {
  const h = pemtohex(pem);
  const p = asn1parse(h);
  const pAlg = dig(p, "seq.1.seq.0.oid") as Record<string, string>;
  const pCurve = dig(p, "seq.1.seq.1.oid") as Record<string, string>;
  if (pAlg === undefined || pCurve === undefined) return null;
  if (asn1oidcanon(pAlg as Record<string, string>) !== "1.2.840.10045.2.1") return null; // not ecPublicKey
  const curveoid = asn1oidcanon(pCurve as Record<string, string>);
  return oidtocurve(curveoid);
}

function pubpemtocurve(pem: string): string | null {
  const h = pemtohex(pem);
  const p = asn1parse(h);
  const pAlg = dig(p, "seq.0.seq.0.oid");
  const pCurve = dig(p, "seq.0.seq.1.oid");
  if (pAlg === undefined || pCurve === undefined) return null;
  if (asn1oidcanon(pAlg as Record<string, string>) !== "1.2.840.10045.2.1") return null; // not ecPublicKey
  const curveoid = asn1oidcanon(pCurve as Record<string, string>);
  return oidtocurve(curveoid);
}

function oidtocurve(oid: string): string | null {
  if (oid === "1.2.840.10045.3.1.7") return "P-256";
  if (oid === "1.3.132.0.34") return "P-384";
  if (oid === "1.3.132.0.35") return "P-521";
  return null;
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
