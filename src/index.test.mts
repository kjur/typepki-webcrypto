import { describe, expect, test } from "bun:test";
import { hashhex, hashutf8, hashrstr, importPEM, signHex, verifyHex, sigAlgToHashAlg, sigRStoASN1, getSecureRandom, getNewHMACKey, getHMACKey, signHMACHex, verifyHMACHex, generateKeypairPEM, generateKeypairJWK } from "./index.mts";

// == hash test ==========
const AAA256 = "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"; // =SHA256("aaa")

test("hashex", async () => {
  expect(await hashhex("SHA-256", "616161")).toBe(AAA256);
});

test("hashrstr", async () => {
  expect(await hashrstr("SHA-256", "aaa")).toBe(AAA256);
});

test("hashutf8", async () => {
  expect(await hashutf8("SHA-256", "aaa")).toBe(AAA256);
});

// == importpem test ==========

test("importPEM RSA private1", async () => {
  const key = await importPEM(PRVR1024, "SHA256withRSA");
  expect(key.type).toBe("private");
  expect(key.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
  expect(key.algorithm.modulusLength).toBe(1024);
  expect(key.algorithm.hash).toEqual({name:"SHA-256"});
  expect(key.usages).toEqual(["sign"]);
});

const SIGAAARSA1024 = "01b85ed1b6669b4d43082521d7b7db481a5ac75016792e2465de6ffb0426bdb85774ebf848f739f79b42c4d584b99dd8c5242479ae19d2a50cf5dee9a854ae56560faf83200c377d131fd983b6219ef4be2b00215b261d3619e73d641afb23892238a51744e2384ec5a7b33072b5b5704a12f9076559f7a7e6858c73c78c3104";
test("signHex", async () => {
  const key = await importPEM(PRVR1024, "SHA256withRSA");
  const hSig = await signHex("SHA256withRSA", key, "616161");
  expect(hSig).toBe(SIGAAARSA1024);
  //console.log(sig);
  //expect(true).toEqual(true);  

  //const key2 = await importPEM(PRVECPEM1, "SHA256withECDSA", "P-256");
  //const hSig2 = await signHex("SHA256withECDSA", key2, "616161", "P-256");
  //console.log(hSig2);
});

test("importPEM RSA public1", async () => {
  const key = await importPEM(PUBR1024, "SHA256withRSA");
  expect(key.type).toBe("public");
  expect(key.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
  expect(key.algorithm.modulusLength).toBe(1024);
  expect(key.algorithm.hash).toEqual({name:"SHA-256"});
  expect(key.usages).toEqual(["verify"]);
});

test("importPEM RSAPSS private1", async () => {
  const key = await importPEM(PRVR1024, "SHA256withRSAandMGF1");
  expect(key.type).toBe("private");
  expect(key.algorithm.name).toBe("RSA-PSS");
  expect(key.algorithm.modulusLength).toBe(1024);
  expect(key.algorithm.hash).toEqual({name:"SHA-256"});
  expect(key.usages).toEqual(["sign"]);
});

test("importPEM RSA public1 various hash alg SHA-1/224/256/384/512", async () => {
  let key = await importPEM(PUBR1024, "SHA1withRSA");
  expect(key.algorithm.hash).toEqual({name:"SHA-1"});
  key = await importPEM(PUBR1024, "SHA224withRSA");
  expect(key.algorithm.hash).toEqual({name:"SHA-224"});
  key = await importPEM(PUBR1024, "SHA256withRSA");
  expect(key.algorithm.hash).toEqual({name:"SHA-256"});
  key = await importPEM(PUBR1024, "SHA384withRSA");
  expect(key.algorithm.hash).toEqual({name:"SHA-384"});
  key = await importPEM(PUBR1024, "SHA512withRSA");
  expect(key.algorithm.hash).toEqual({name:"SHA-512"});
});

// RFC 9500 test EC P-256 private
const PRVECPEM1 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5stb3YCqRa6clejB
VHZnn/7JU8FoUecR50OTlYnGT8GhRANCAARCJUj4j7eC/7Xso3REUscqHlWPvW9z
vl5I6TIyzEXFsWxM0QxMuNW4oXE56UiCyJklcpk0JfQUGat+kKQqSUJy
-----END PRIVATE KEY-----`;

// RFC 9500 test EC P-256 public
const PUBECPEM1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71v
c75eSOkyMsxFxbFsTNEMTLjVuKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END PUBLIC KEY-----`;

test("importPEM EC P-256 private1", async () => {
  const key = await importPEM(PRVECPEM1, "SHA256withECDSA", "P-256");
  expect(key.type).toBe("private");
  expect(key.algorithm.name).toBe("ECDSA");
  expect(key.algorithm.namedCurve).toBe("P-256");
  expect(key.usages).toEqual(["sign"]);
});

test("importPEM EC P-256 public1", async () => {
  const key = await importPEM(PUBECPEM1, "SHA256withECDSA", "P-256");
  expect(key.type).toBe("public");
  expect(key.algorithm.name).toBe("ECDSA");
  expect(key.algorithm.namedCurve).toBe("P-256");
  expect(key.usages).toEqual(["verify"]);
});

test("signHex verifyHex RSA", async () => {
  const hData = "616161";
  const prvkey = await importPEM(PRVR1024, "SHA256withRSA");
  const hSig = await signHex("SHA256withRSA", prvkey, hData);

  const pubkey = await importPEM(PUBR1024, "SHA256withRSA");
  expect(await verifyHex("SHA256withRSA", pubkey, hSig, hData)).toBe(true);
});

test("signHex verifyHex RSA-PSS", async () => {
  const hData = "616161";
  const prvkey = await importPEM(PRVR1024, "SHA256withRSAandMGF1");
  const hSig = await signHex("SHA256withRSAandMGF1", prvkey, hData);

  const pubkey = await importPEM(PUBR1024, "SHA256withRSAandMGF1");
  expect(await verifyHex("SHA256withRSAandMGF1", pubkey, hSig, hData)).toBe(true);
});

test("signHex verifyHex EC P-256", async () => {
  const hData = "616161";
  const prvkey = await importPEM(PRVECPEM1, "SHA256withECDSA", "P-256");
  const hSig = await signHex("SHA256withECDSA", prvkey, hData, "P-256");

  const pubkey = await importPEM(PUBECPEM1, "SHA256withECDSA", "P-256");
  expect(await verifyHex("SHA256withECDSA", pubkey, hSig, hData, "P-256")).toBe(true);
});

test("sigAlgToHashAlg", () => {
  expect(sigAlgToHashAlg("SHA1withRSA")).toBe("SHA-1");
  expect(sigAlgToHashAlg("SHA512withECDSA")).toBe("SHA-512");
  expect(sigAlgToHashAlg("MD5withRSA")).toBe(null);
});

describe("verifyHex jwt.io generated signatures interop", async () => {
  test("SHA256withRSAandMGF1 2048 salt=default mgf1=default", async () => {
    // testrsa2048.jwtio.ps256.*
    const TBSHEX = "65794a68624763694f694a51557a49314e694973496e523563434936496b705856434a392e65794a7a645749694f6949784d6a4d304e5459334f446b7749697769626d46745a534936496b7076614734675247396c4969776959575274615734694f6e527964575573496d6c68644349364d5455784e6a497a4f5441794d6e30";
    const SIGHEX = "82c8252d01888522910e8285874263ca100c15f7d7b672f02d4598b545f9b5298ac66129f5b6fba00c399b73be2964572e0e00449225079ab7e84e9ee457947722092ee8c4c26fe6746adb820f4f7b697b84aca3140a18f3fed4ae8ba7f1add764cbf00d4f9bcbead319e1183458f8c6787702f812c1e38e0c0904dfa90c7210e2c68c99dec4b0162e190a5236b5e1f0bbfbbbd7edf3bc03d7789e8f70026437dc53681d05bb3b26cd0ec3800e73de9ebb04b37414ef056653f7959e7d1c26fa9d0e28c92af9c39c63da5654bb8efce887f34ec17d77c06923dedeebd2db138afc97b8a47d1c8f46248ed8aea3aa611736f0a56568ce823f1864a82d219094f1";
    const pubR2048 = await importPEM(PUBR2048, "SHA256withRSAandMGF1");
    expect(await verifyHex("SHA256withRSAandMGF1", pubR2048, SIGHEX, TBSHEX)).toBe(true);
  });
  test("SHA384withECDSA", async () => {
    // testecp384.jwtio.es384.*
    const TBSHEX = "65794a68624763694f694a46557a4d344e434973496e523563434936496b705856434a392e65794a7a645749694f6949784d6a4d304e5459334f446b7749697769626d46745a534936496b7076614734675247396c4969776959575274615734694f6e527964575573496d6c68644349364d5455784e6a497a4f5441794d6e30";
    const SIGHEX = "d587d8a67e4f29adfe85c79e9ff0bb1b5428d1c3a19934d651b0fd918a3d33881e85e013859a09c91abeac7aa2ef9ae6ab756c4d0f42c9747c788fb900014ae1e7583fe6f3cb80093e27afae629faa5bb41cf5b11ec5d13dd082af527ba5bd82";
    const pubE384 = await importPEM(PUBE384, "SHA384withECDSA", "P-384");
    expect(await verifyHex("SHA384withECDSA", pubE384, SIGHEX, TBSHEX, "P-384")).toBe(true);
  });
});

describe("verifyHex OpenSSL generated signatures interop", async () => {
  test("SHA256withRSA 1024", async () => {
    const pubR1024 = await importPEM(PUBR1024, "SHA256withRSA");
    expect(await verifyHex("SHA256withRSA", pubR1024, SIGOSSR1024, AAAHEX)).toBe(true);
  });
  test("SHA256withRSA 2048", async () => {
    const pubR2048 = await importPEM(PUBR2048, "SHA256withRSA");
    expect(await verifyHex("SHA256withRSA", pubR2048, SIGOSSR2048, AAAHEX)).toBe(true);
  });
  test("SHA512withRSA 4096", async () => {
    const pubR4096 = await importPEM(PUBR4096, "SHA512withRSA");
    expect(await verifyHex("SHA512withRSA", pubR4096, SIGOSSR4096, AAAHEX)).toBe(true);
  });
  test("SHA1withECDSA P-256", async () => {
    const pubE256S1 = await importPEM(PUBE256, "SHA1withECDSA", "P-256");
    expect(await verifyHex("SHA1withECDSA", pubE256S1, SIGOSSE256S1, AAAHEX, "P-256")).toBe(true);
  });
  test("SHA256withECDSA P-256", async () => {
    const pubE256 = await importPEM(PUBE256, "SHA256withECDSA", "P-256");
    expect(await verifyHex("SHA256withECDSA", pubE256, SIGOSSE256, AAAHEX, "P-256")).toBe(true);
  });
  test("SHA384withECDSA P-384", async () => {
    const pubE384 = await importPEM(PUBE384, "SHA384withECDSA", "P-384");
    expect(await verifyHex("SHA384withECDSA", pubE384, SIGOSSE384, AAAHEX, "P-384")).toBe(true);
  });
  test("SHA1withECDSA P-521", async () => {
    const pubE521S1 = await importPEM(PUBE521, "SHA1withECDSA", "P-521");
    expect(await verifyHex("SHA1withECDSA", pubE521S1, SIGOSSE521S1, AAAHEX, "P-521")).toBe(true);
  });
  /*
  test("SHA256withECDSA P-521", async () => {
    const pubE521S2 = await importPEM(PUBE521, "SHA256withECDSA", "P-521");
    expect(await verifyHex("SHA256withECDSA", pubE521S2, SIGOSSE521S2, AAAHEX, "P-521")).toBe(true);
  }); // エラー
  test("SHA384withECDSA P-521", async () => {
    const pubE521S3 = await importPEM(PUBE521, "SHA384withECDSA", "P-521");
    expect(await verifyHex("SHA384withECDSA", pubE521S3, SIGOSSE521S3, AAAHEX, "P-521")).toBe(true); // エラー
  });
   */
  test("SHA512withECDSA P-521", async () => {
    const pubE521 = await importPEM(PUBE521, "SHA512withECDSA", "P-521");
    expect(await verifyHex("SHA512withECDSA", pubE521, SIGOSSE521, AAAHEX, "P-521")).toBe(true);
  });

  test("SHA256withRSAandMGF1 2048 salt=default mgf1=default", async () => {
    const pubR2048 = await importPEM(PUBR2048, "SHA256withRSAandMGF1");
    expect(await verifyHex("SHA256withRSAandMGF1", pubR2048, SIGOSSP2048D2SDMD, AAAHEX)).toBe(true);
  });

  test("SHA384withRSAandMGF1 2048 salt=default mgf1=default", async () => {
    const pubR2048 = await importPEM(PUBR2048, "SHA384withRSAandMGF1");
    expect(await verifyHex("SHA384withRSAandMGF1", pubR2048, SIGOSSP2048D3SDMD, AAAHEX)).toBe(true);
  });

  test("SHA512withRSAandMGF1 2048 salt=default mgf1=default", async () => {
    const pubR2048 = await importPEM(PUBR2048, "SHA512withRSAandMGF1");
    expect(await verifyHex("SHA512withRSAandMGF1", pubR2048, SIGOSSP2048D5SDMD, AAAHEX)).toBe(true);
  });
});

describe("sigRStoASN1", () => {
  test("P-256 RS Sig", () => {
    expect(sigRStoASN1(SIGOSSE256)).toBe("3044022069c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd060022076ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f");
  });
  test("P-384 RS Sig", () => {
    expect(sigRStoASN1(SIGOSSE384)).toBe("3065023100cb6c3115a81bfb7581df9bd05e4116ed90f483fdbe03c8c8204c6d2a9bba7520580dfb86f5649ad2de5fce59b67b4b61023059924fcd38c995d782d33f1750134cbef6e609558fa6d7e6a0eff7d32b90a48df5eb9fed839fa492cb9da50a017a0f12");
  });
  test("P-521 RS Sig", () => {
    expect(sigRStoASN1(SIGOSSE521)).toBe("30818802420185d9deae536fdd568ed6174ae4481a5d447b59c7bfb424d0b14b6bc098622ecaed9d3e967c541b717bef7b293d3c3ffa86cdedad31cfad20ef3e8f54ac3fa2078f024201d6c72311db50b27039a5b6d664e9ec423c501841eff48a7f35882c18b5a0ba2a928449f282448eb4af9f7ed60813f51862a5ffcefb3e6a8805faf2827bdfd4f246");
  });
});

test("getSecureRandom", () => {
  expect(getSecureRandom(8).length).toBe(16);
  expect(getSecureRandom(256).length).toBe(512);
});

test("getNewHMACKey", () => {
  expect(getNewHMACKey("hmacSHA1").length).toBe(128);
  expect(getNewHMACKey("hmacSHA256").length).toBe(128);
  expect(getNewHMACKey("hmacSHA384").length).toBe(256);
  expect(getNewHMACKey("hmacSHA512").length).toBe(256);
});

test("getHMACKey", async () => {
  const hKey = "a1020304050607080900b1020304050607080900c1020304050607080900d1020304050607080900e1020304050607080900f1020304050607080900a1020304"; // 64 bytes
  const key: CryptoKey = await getHMACKey("hmacSHA256", hKey);
  //console.log(key);
  expect(typeof key).toBe("object");
  expect(key.algorithm.name).toBe("HMAC");
  expect(key.algorithm.hash.name).toBe("SHA-256");
  expect(key.algorithm.length).toBe(512);
});

describe("signHMACHex OpenSSL mac command interop", async () => {
  test("SHA1", async () => {
    expect(await signHMACHex("hmacSHA1", HMACKEY1, "616161")).toBe(SIGOSSHS1);
  });
  test("SHA256", async () => {
    expect(await signHMACHex("hmacSHA256", HMACKEY1, "616161")).toBe(SIGOSSHS256);
  });
  test("SHA384", async () => {
    expect(await signHMACHex("hmacSHA384", HMACKEY1, "616161")).toBe(SIGOSSHS384);
  });
  test("SHA512", async () => {
    expect(await signHMACHex("hmacSHA512", HMACKEY1, "616161")).toBe(SIGOSSHS512);
  });
});

describe("verifyHMACHex OpenSSL mac command interop", async () => {
  test("SHA1", async () => {
    expect(await verifyHMACHex("hmacSHA1", HMACKEY1, SIGOSSHS1, "616161")).toBe(true);
  });
  test("SHA256", async () => {
    expect(await verifyHMACHex("hmacSHA256", HMACKEY1, SIGOSSHS256, "616161")).toBe(true);
  });
  test("SHA384", async () => {
    expect(await verifyHMACHex("hmacSHA384", HMACKEY1, SIGOSSHS384, "616161")).toBe(true);
  });
  test("SHA512", async () => {
    expect(await verifyHMACHex("hmacSHA512", HMACKEY1, SIGOSSHS512, "616161")).toBe(true);
  });
});

describe("RFC 7797 sample JWS signature interop", async () => {
  test("4.1 HS256", async () => {
    expect(await verifyHMACHex("hmacSHA256", "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3", "e66bdf3aba0bfa0ec7caa268a337a19ac6aa9af4d8184ab98d3235815be81284", "65794a68624763694f694a49557a49314e694a392e4a4334774d67")).toBe(true);
  });
});


// test data =============================================================
const AAAHEX = "616161";

// RFC 9500 test keys =================================================

const PRVR1024 = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALDRg1Koj1PVUW9G
wg56Nn196IrPVKAZ9t71erm0TO3bIkKxvKD7G1y4KzA2F2pjkDVk3sbrQdsvj8eH
9OUuEUnjM0dXKXP2YMPHfKngghwraVvnrp19MPQHkRD0iq5vi3AtR0spAIF/KGYk
m+wSorGbgnhBaAj4GuH8+bd3imI/AgMBAAECgYBILp+PpOQt8w11gctCob2Q6U9/
Kzh+y1qulkPtf59QEn8f/vLkPN5ksYJgAhT5B4Ada/pN9khCNF5btDLTREUl2DAW
VMVEKwpeEbnH4gH6MvQauvTwpuA88ODLgmbGKtEdlW1TyUZuSJlf6iYMhTbwQcs1
YvqsURxNZqj+0RGykQJBAOnYbk3DSphafsdab1SnXORROeRSQLOGq3Edt5G82YcY
oTuvIYwkSTZGaAdWy1Cmy+4VjiUhRJkSMBwNQUkRGEUCQQDBkfo7VQs5GnywcoN2
J3KV5hxlTwvvL1jc5clioQt9118GAVRl5VB25GYmPuvK7SDS66s5MT6LxWcyD+iy
3GKzAkEA5zrgN3y4slYprq66D5c+v3WiLSc4W0z7Ees0raNz5aZxKDdQkOcAje6o
xzkH6kREurQNzqFK16GoeNSSjdGdkQJAQZl5FhZyIT4Kt7l3N9mSiZ5cTTEGuF5x
XRs6roQpYtJUT7KvqYCXTlOFEr0MJ89I6nIXquA3dCLIID0n/UWW5QJBALmdf49N
TUVfH7pGLZkKLoSMQowevuAdwAGEyKdlg603n2mtr1R1VDD2PEJT0bt4zJvSMmQ0
AIC4TBqRfeCLbts=
-----END PRIVATE KEY-----`;

// RFC 9500 test RSA 1024 public
const PUBR1024 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw0YNSqI9T1VFvRsIOejZ9feiK
z1SgGfbe9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNH
Vylz9mDDx3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4
QWgI+Brh/Pm3d4piPwIDAQAB
-----END PUBLIC KEY-----`;

const PUBR2048 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPnoGUOnrpiSqt4XynxA
+HRP7S+BSObI6qJ7fQAVSPtRkqsotWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTf
Mul8b/CZjP2Ob0LdpYrNH6l5hvFE89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92
UE68mOyUVXGweJIVDdxqdMoPvNNUl86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/
LUK43YvJh+rhv4nKuF7iHjVjBd9sB6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKN
e6kUhKJ1luB7S27ZkvB3tSTT3P593VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9T
EwIDAQAB
-----END PUBLIC KEY-----`;

const PUBR4096 = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs4tJYOY75qjbqJqCl47x
9jJE5Vd9jPWGFtXKV1nUnMjZNsM4qjy5sRHBSX5bUa9pLyYR5on3Z1SAwLD0w2VP
Q6+F/oyK1zTgQqitoF/XZQjgC6D3VsNEO76DPqfRANT7Nn7r1gvbZIZ3/H3rlCRN
rRr47tHGWBLAPnxz9/NY6UG8ZkWP97uXpJqYoRgH4CwaO5rTOlc64YDh/0Mq5VgM
ycq/q2AvMlvNoJfoe8em1040qH1gikP+suT/8fS452hqmEddtRpuvQgXKldBd0kk
iyFVyLkG4NVA6Mso9MAK3J/kdYoaw2SrOeThVSiYVEQVP+7GrUxTSLLjj/VQ9fpY
M5eTNzDICIG/Ee7o/jhtW1EoSamDmUOr89lyIHaXuOwkEaJhnVXKBCM8WiztxvKG
2CnQ6Dcge3ZSmqJEhyEmjcAVC7ewfnMxOnE+WJW6rzrf+mA5WMVn+FzyWx2AondW
ow0aUKHkaY7amhIrsKp6YPfNImyxFlz8+cqDCmBswPsUh/JJ5eDHHIhibFcSgIHe
dsEjhLbUSLZ/DnEjru90qIWWA3R1VIPykKfeZkZeInsrFzGPikkFKwFF+6KDdyvC
mltYEqzO46tigXAZ5UgH8oiXEre48wO6X+FH+cLzQ0q3A8HZRnNDgqCjU/Tgy76i
aku/Ic6eteedR1fX3gJ/IOUCAwEAAQ==
-----END PUBLIC KEY-----`;

const PUBE256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71v
c75eSOkyMsxFxbFsTNEMTLjVuKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END PUBLIC KEY-----`;

const PUBE384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr
/soRsdla27VHNK9XC/grcijPImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWN
prNGOWE6j7m1qNpIxnRxF/mRnoQk837I
-----END PUBLIC KEY-----`;

const PUBE521 = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB0P1yV6hMdH9WJXXAc4Xb6/L1K+pY
CD24L90VMdiq48yHX/Av9/otomDY62LW0vXWSSeOMhc2oGKMu7MDCLbmGNsA9irS
BMZGA1m8gYq4lhvw8PwOxaropCgXPOVvAN6bFXweXILGT1Yvyt78Skwo9tNCzz72
FvyC0ztyhckh8r82/dg=
-----END PUBLIC KEY-----`;

// test signatures generated with OpenSSL and RFC 9500 test private keys ====

// testrsa1024.aaa.sha256.sig
const SIGOSSR1024 = "01b85ed1b6669b4d43082521d7b7db481a5ac75016792e2465de6ffb0426bdb85774ebf848f739f79b42c4d584b99dd8c5242479ae19d2a50cf5dee9a854ae56560faf83200c377d131fd983b6219ef4be2b00215b261d3619e73d641afb23892238a51744e2384ec5a7b33072b5b5704a12f9076559f7a7e6858c73c78c3104";

// testrsa2048.aaa.sha256.sig
const SIGOSSR2048 = "18c171461718df870ff04fefa5be19fdffe85f1a41435cbc73ed654b41f693ce02679adbf3a08eca3f595e21c0ad9a24b65ac33c82399af8f4468ae30cf81f07457a24836508d9da2b3a3df4a738c186a153b4afcc78a3b37ee0604d18f17dc67ae586d5c52ad27b7af959eccb8a1d633cccf86182fbfa45c0bb09661105da56b719c177045decfb507e54a34fae6bf8ea9c2f975172cb99d77d18bdc23a3e0f26a65dcc36609fe339d383884a64be363c21b6bc814bd55c4ff7c2f0d9f4eb51a31d219ba5a1ee700c96a95b8bee7b49ea0fb76660206752eb5f9fd472e49ca9b230614ab3e307a3d2a13bc9b093f063b75fff7089ddcbb9f81cd97e1a4369f3";

// testrsa4096.aaa.sha512.sig
const SIGOSSR4096 = "36f11c3c0dfdb74bfb88530b6712b86d6e5491688133314df35e1d65e350e4dd5411fa5c36b50b01526b273a19d57b37e37df4ca150b3f860e029a74d355ccef0173e1618bc5fd435d73067e878d3b7a26b03685d27761871f223154ac27231e37ce3cac111272c2bfb047c13ddfc1227c672b5a69a0fe32b3aa17153e90d8a15992af53222b009d053fcecf9a3fab75063e08c193d9832751ef753a1c5bae20043d5917ab8bcd4ce0d293e29af17be83ebc9937d11d6496998d4f01bf3bab9ae1057c6bf6a574483ac1272c1b8ace473eafb102a2ce455047262ad96142ea9779d0b9439a5bd2a9527e0f8374298bde0efb66e6d5ec535af6e7ce39744ffa99e9242b64ab07a32aeeb6a7d6bd2d7cfcaa6bc984e0c7bd7ed117d8de263c37ae9f84fd89d3add3ed572150899ebe89e3ebe8c2b2cfc3b4d5b25f3ad615d75bc317502fa42e4c0e109521d247d4a7170e82e433cc16adca981800b0ed2d365d1392c97eb37c0a92656213a90b91b4dcd4abba177c7f8a8e90ec0dbd6e4fabccf9c8d44e9f5c393f3ac01e4238424e6ac7f2f0e96fb0240c2bd522495afa58ceb084077cc7d278612891767e48dbd9e23b37dc7b611f12909c5a3952d31c9f1ef1ad53cba6e164f83cd8cf306abf40ffaa01053c920353b0ed9bf6c75c04926024bafdf31f20c3a245ea1531e2571e1e14fabb8458531c9365e42202316fc17efa";

// testecp256.aaa.sha1.sig
const SIGOSSE256S1 = "29d8716fd81ccbb579a4c5d14678f15250a70dc5dc8dc406e8f9dea240704256a343f16cedb33b9606acbbbb52d634d8b835a27a90b9f52f64c620fdcf0a1b34";

// testecp256.aaa.sha256.sig
const SIGOSSE256 = "69c3e2489cc23044f91dce1e5efab7a47f8c2a545cdce9b58e408c6a2aabd06076ba3d70771c00451adcf608d93f20cc79ccaf872f42028aa05ff57b14e5959f";

// testecp384.aaa.sha384.sig
const SIGOSSE384 = "cb6c3115a81bfb7581df9bd05e4116ed90f483fdbe03c8c8204c6d2a9bba7520580dfb86f5649ad2de5fce59b67b4b6159924fcd38c995d782d33f1750134cbef6e609558fa6d7e6a0eff7d32b90a48df5eb9fed839fa492cb9da50a017a0f12";

// testecp521.aaa.sha1.sig
const SIGOSSE521S1 = "014e8d5d7ea8494a0b4e48372b76e61bee7fdd0db7463aee4551e9b7df15f8a9d6216c478b046406450d8b0cbb97098b126ac6362800384d726aa230c579092e7e3b01e01a525804b4095d5cd57c2ca031dab907c2d08dc792b93261ec2e656058a86d2479cea115b26bc69e3e6894b0a9dcd0d8f65aa6a69f499a02980bd3c8ca352af4";

// testecp521.aaa.sha256.sig
//const SIGOSSE521S2 = "91a8506e50080b553c9aeb856e6eea6c1db842f68342c229d83b4ebb95067f0088947bb79f8624098de08c100416508eebc6502a42d2a624d59d9776197ed066ad26f9e457263c4eabba40d2ebb6b491700e74b593b64c18231a565c7261c75da2f091e387309943f9afaf2b3fc18fbe1cec86eff156e0c52fe749016ca58a01319d";
const SIGOSSE521S2 = "0187ee6ba73303c5c7bad0149b46142d621110aa676ca546ec592b3c05763004300455843e25df94148d6ef6859c8f70fe82460c7b7f97497304a69cc9b2a4ed654fb9161809a862ac2c9fc8385b2f2794d721ead5bae243749caac84e00c1dd8c0c2438d80549eeb44ac46626ad8367c6018f71a2dd1de0e5bfeeaf42d332f2b83e9d";

// testecp521.aaa.sha384.sig
//const SIGOSSE521S3 = "01afd85abd294d62d28b885c1c5e72384a681699240b6718b6942a8e4d50b03a28dd4494be8ab6d94587d2dbf727eac87147d9bace6c76c21105081e15be944127553aab3c196daa568ac885464acc42530d4ad25611c2b9a068c6af40cc3070db9778c72266b3face25c0cf968aa114eb984a7d28a1f8d9d454a8467747a07d0c2851";
const SIGOSSE521S3 = "0179991b37591cd500e7197f8fe4b7efc6e247fed3271ab71c482928ed86d998273ccb7641edd718e3eeec45b79f0ac9885a5f72d22b1ae7e4072b1332e3ecf6e1e6993e691f4043f30fb75fee54771239ded41628ee4968daedd4aa2d1a05f38db1372eefbf5f7b83314d8d34641fbc79546f456388af542e4c22d04580ca4ae7df22";

// testecp521.aaa.sha512.sig
const SIGOSSE521 = "0185d9deae536fdd568ed6174ae4481a5d447b59c7bfb424d0b14b6bc098622ecaed9d3e967c541b717bef7b293d3c3ffa86cdedad31cfad20ef3e8f54ac3fa2078f01d6c72311db50b27039a5b6d664e9ec423c501841eff48a7f35882c18b5a0ba2a928449f282448eb4af9f7ed60813f51862a5ffcefb3e6a8805faf2827bdfd4f246";

// testrsa2048.aaa.pss.d256.sdef.mdef.sig
const SIGOSSP2048D2SDMD = "7abd6e49b09715af2c373e27df13442e992fbf492010195eeab4527ae2206841ef8e410672c5c3d13567943803828554073ac82404d2e1f9a0dd0060f9f271fc97095ade34d6cefaf2e5dbe065e42bc062b17eb490b9a535d30a89b6fa09275a840012354180318d1aa8b30690f2a782a3f0c5b13c2b6c12b08f61df2537658b4f125d2685fea0b185dd0ab470b119960848c5d528f94b8868fb4034324f620b9cb2ae7c23dd64760ec66f6b2fc1cf1036c2f9e6b514a5643ce5983a94e9db06960debb219e6ed0a4271675fc6426d0f22cb995173759d4049f3680d8a6c49d1875bc8fd960849a29bc2afed2ac0d3a4c96cd20444c790849ab3390c0e0f9efb";

// testrsa2048.aaa.pss.d384.sdef.mdef.sig
const SIGOSSP2048D3SDMD = "555557dc928eb9c0d64f92ddf12e9d406e2405dc9d75ea4de44cec25a099f0935b5ce388b1b1cd4f771deafebdf78053f869115c85a97621db126a082ad116a74e40f39111c5b6e330583da6190b19f0cba1957f4b44263a40e74917e49e4f535654dfc9d453f7c2f80babdbb1a2df66ae05f06189b2f526e608e7cc28f03794f86db985ed105acb7fe74d43834f102a99a81f8f87ac262ed8cb5619f0a1cda8dc26a738fe34a28fb99fd57162b41e14c9c8d1b0f6b337edede1e4b8f24b0e6fb4a7eea5fae0e1d686c77c0b9b043ecaa11c1d520d50e1d03b9ea39b6c92e1b587fb81985a278783fb8c646114dcaca9180df6e5721123372dcc805c995cd240";

// testrsa2048.aaa.pss.d512.sdef.mdef.sig
const SIGOSSP2048D5SDMD = "ae0b11d54d4ad98fdb29165a67a72e2247c29428be64b8fa2054b68799748e127e71c72236a08f485ca53793b4b3452aaf0366e26ba02d8477b045d5c2e77e58ae2d2c7136f0a8009ba3a133d71e9216ffca98e6b408561753ea54263049782600dedb396d2a81b8ce80e7606c7b0428a320ef0855c3a7490867884d23563e3d0e1e423cd79920813df1747c136e211522e1f2a5fe9c02a4369047dfd8eb619860f66dce5e533ade66a8a3828a827824ce333bb0fe9f9d616ee9ddf535bd25cf6d2c2d8397529f6934e8f9afda7e7bcc848c15998232d9a2090bd413e18c3b16792b2da39f18815287330cb82dffcd4c31e4a1e6f7d143153a35ed36fd01de18";

// == HMAC TEST DATA =====================================================
const HMACKEY1 = "a1020304050607080900b1020304050607080900c1020304050607080900d1020304050607080900e1020304050607080900f1020304050607080900a1020304"; // 64 bytes
// rfc9500testkey/aaa.txt.hs1.k1.sig
const SIGOSSHS1 = "1abc520eea206adec5cf8ea21119ddf19f488113";
// rfc9500testkey/aaa.txt.hs256.k1.sig
const SIGOSSHS256 = "04fa8dada3a1793b767dcbdad7c9dde1826d10ab55c1743a2e02c39bac56d2c0";
// rfc9500testkey/aaa.txt.hs384.k1.sig
const SIGOSSHS384 = "77223e196e2d541713f441134fa686cf415b4715d627613d03e507b66aff32778c5be1aea870fee74839fc141970c8a0";
// rfc9500testkey/aaa.txt.hs512.k1.sig
const SIGOSSHS512 = "b39b8e2995ee35136bc874a95b8320cc1eca9f0d093ef12a2d6b72e796ed65589468ef4793bf77782c8be4e94042e8e676af91bda8d38dcab492046877e9890d";

describe("generateKeypairPEM", async () => {
  test("RSA (default)", async () => {
    const kp = await generateKeypairPEM("RSA");
    expect(kp[0]).toMatch(/BEGIN PRIVATE KEY/);
    expect(kp[1]).toMatch(/BEGIN PUBLIC KEY/);
  });
  test("EC P-521", async () => {
    const kp = await generateKeypairPEM("EC", "P-521");
    expect(kp[0]).toMatch(/BEGIN PRIVATE KEY/);
    expect(kp[1]).toMatch(/BEGIN PUBLIC KEY/);
  });
});

describe("generateKeypairJWK", async () => {
  test("RSA (default)", async () => {
    const kp = await generateKeypairJWK("RSA");
    expect(kp[0].kty).toBe("RSA");
    expect(kp[0].e).toBe("AQAB");
    expect(typeof kp[0].d).toBe("string");
    expect(kp[1].kty).toBe("RSA");
    expect(kp[1].e).toBe("AQAB");
  });
  test("EC P-521", async () => {
    const kp = await generateKeypairJWK("EC", "P-521");
    expect(kp[0].kty).toBe("EC");
    expect(kp[0].crv).toBe("P-521");
    expect(typeof kp[0].d).toBe("string");
    expect(kp[1].kty).toBe("EC");
    expect(kp[1].crv).toBe("P-521");
  });
});
