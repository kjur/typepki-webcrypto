typepki-webcrypto: W3C Web Crypto API helper function sub module for TypePKI library
====================================================================================

The 'TypePKI' library is an opensource free TypeScript PKI library which is the successor of the long lived [jsrsasign](https://kjur.github.io/jsrsasign) library.

The 'typepki-webcrypto' is W3C Web Crypto API [[1]](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)[[2]](https://www.w3.org/TR/WebCryptoAPI/) helper function sub module for TypePKI library. 

## FEATURE
- easy use for
  - keypair/key generation
  - key import
  - signing and verification
  - PEM key format
- Dual CommonJS/ES module package supporting CommonJS(CJS) and ES modules

## Signing
The {@link signHex} function can sign a data with RSA, RSA-PSS and ECDSA algorithms very easily.

### RSA signing
Here is an example to sign a string "apple りんご":
```JavaScript
const pemPrivateKey = `-----BEGIN PRIVATE KEY-----
MI...
-----END PRIVATE KEY-----`;
(async () = {
  const privateKey = await importPEM(pemPrivateKey, "SHA256withRSA");
  const hexSignatureValue = await signHex("SHA256withRSA", privateKey, utf8tohex("apple りんご"));
})();
```
The [typepki-strconv](https://kjur.github.io/typepki-webcrypto/) provides many functions convert any data to a hexadecimal string such as
[ArrayBuffer](https://kjur.github.io/typepki-strconv/functions/ArrayBuffertohex.html), [Base64](https://kjur.github.io/typepki-strconv/functions/b64tohex.html), [Base64URL](https://kjur.github.io/typepki-strconv/functions/b64utohex.html) or [raw string](https://kjur.github.io/typepki-strconv/functions/rstrtohex.html).

## Signature Verification
The {@link verifyHex} function can verify a RSA, RSA-PSS and ECDSA signature very easily too.

### RSA signature verification
Here is an example to verify a RSA signature for a string "apple りんご":
```JavaScript
const pemPublicKey = `-----BEGIN PUBLIC KEY-----
MI...
-----END PRIVATE KEY-----`;
const hexSignature = "12ab...";
(async () = {
  const publicKey = await importPEM(pemPublicKey, "SHA256withRSA");
  const isValid = await verifyHex("SHA256withRSA", publicKey, hexSignature, utf8tohex("apple りんご"));
})();
```


