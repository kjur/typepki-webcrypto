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

## Notes for ECDSA signature format
ECDSA signature value has two types of encoding:

- R and S value concatinated encoding used in "typepki-webcrypto", W3C Web Crypto API or JSON Web Signature.
- ASN.1 SEQUENCE of INTEGER R and S value used in OpenSSL or Java

Here is a ASN.1 dump of OpenSSL or Java's ECDSA signature value which consists R and S integer value:
```
SEQUENCE {
  INTEGER
    28 AE 0E 46 36 FE 21 53 1B 05 AC BF 66 D1 C5 91
    9A D8 69 29 78 52 D7 2F F2 F4 A1 06 0F 2D 56 32
  INTEGER
    00 C2 C8 75 D9 60 0C DC 56 FB 43 39 DB 1E 00 FF
    64 2D ED A5 44 21 88 D3 3F 68 1D A6 E4 38 F4 4E
    EA
  }
```
Note that its S value starts 0x00 because ASN.1 Integer
value uses two's complement encoding and positive integer's
first byte is bigger than 0x7f, 0x00 will be added.

ASN.1 encoded value will be following in hexadecimal:
```
3045
  0220
    28ae0e4636fe21531b05acbf66d1c5919ad869297852d72ff2f4a1060f2d5632
  0221
    00c2c875d9600cdc56fb4339db1e00ff642deda5442188d33f681da6e438f44eea
```

The "typepki-webcrypto", JWS or W3C Web Crypto API will use R and S concatinated signature value.
For W3C Web Crypto API, above signature will be encoded as following:
```
28ae0e4636fe21531b05acbf66d1c5919ad869297852d72ff2f4a1060f2d5632
c2c875d9600cdc56fb4339db1e00ff642deda5442188d33f681da6e438f44eea
```
Note that there is no 0x00 in front of S's value.

So when you need to exchange signatures among W3C Web Crypto API and OpenSSL, you need to convert ECDSA signature value.
In such case, "typepki-webcrypto" provides converter functions:
- {@link sigRStoASN1}
- {@link sigASN1toRS}

## Notes for RSA-PSS salt length
W3C Web Crypto API requires an explict salt length for RSA-PSS signature. It means there is no default value.
So the "typepki-webcrypt" functions use the default salt length value as the same as W3C Web Crypto API.
Their values are the same as using hash algorithm byte length.

OpenSSL `pkeyutl` command can be specified [`rsa_pss_saltlen`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html#rsa_pss_saltlen:len) option for signing and verifying RSA-PSS signature.

Here is a summary for salt length:

|                     |SHA1+PSS|SHA256+PSS|SHA384+PSS|SHA512+PSS|
|---------------------|-------------|-------------|-------------|-------------|
|saltlen in W3C Crypto|need explicit|need explicit|need explicit|need explicit|
|typepki default|20|32|48|64|
|OpenSSL saltlen=digest(default)|20|32|48|64|
|OpenSSL RSA key byte len + saltlen=max|keylen-22|keylen-34|keylen-50|keylen-66|
|OpenSSL RSA2048 saltlen=max|234|222|206|190|
|JWA/JWS|-|32|48|64|

For OpenSSL's `rsa_pss_saltlen:max`, its salt value will be calculated as follows:
```
saltlen = key_byte_length - hash_byte_length - 2
```
For example of RSA 2048bit, RSA-PSS, hash=SHA1(20bytes), mgf=SHA1 and saltlen=max, then:
```
saltlen = 256 - 20 - 2 = 234
```

Thus, when you want to verify a signature generated by OpenSSL with RSA-PSS and saltlen=max,
you need to explictly specify salt length with the number.
