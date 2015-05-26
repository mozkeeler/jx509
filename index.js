var forge = require('node-forge');

function base64ToPEM(base64) {
  var chunks = base64.split(/(.{64})/);
  var output = "-----BEGIN CERTIFICATE-----";
  chunks.forEach(function(chunk) {
    if (chunk) {
      output += "\n" + chunk;
    }
  });
  output += "\n-----END CERTIFICATE-----";
  return output;
}

function getDNField(dn, field) {
  var field = dn.getField(field);
  if (field) {
    return field.value;
  }
  return null;
}

function hashBytes(forgeDigestType, data) {
  var digest = forgeDigestType.create();
  digest.start();
  digest.update(data);
  return digest.digest().toHex();
}

exports.x509ToJSON = function(base64) {
  var pem = base64ToPEM(base64);
  var cert = forge.pki.certificateFromPem(pem);
  if (!cert) {
    throw "Should be able to decode a simple certificate";
  }
  console.log(cert);
  var certDER = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  var result = {
    issuerCN: getDNField(cert.issuer, 'CN'),
    issuerOU: getDNField(cert.issuer, 'OU'),
    issuerO: getDNField(cert.issuer, 'O'),
    issuerC: getDNField(cert.issuer, 'C'),
    subjectCN: getDNField(cert.subject, 'CN'),
    subjectOU: getDNField(cert.subject, 'OU'),
    subjectO: getDNField(cert.subject, 'O'),
    subjectC: getDNField(cert.subject, 'C'),
    sha1Fingerprint: hashBytes(forge.md.sha1, certDER),
    sha256Fingerprint: hashBytes(forge.md.sha256, certDER),
    notBefore: cert.validity.notBefore.toUTCString(),
    notAfter: cert.validity.notAfter.toUTCString(),
    version: cert.version + 1,
  };
  return result;
};

exports.powerOnSelfTest = function() {
  var b64 = "MIIBEDCBuwICAP8wDQYJKoZIhvcNAQEFBQAwFDESMBAGA1UEAxMJbG9jYWxob3N0" +
            "MB4XDTE1MDIwNjAxMDg1MFoXDTIzMDYwNjAxMDg1MFowFDESMBAGA1UEAxMJbG9j" +
            "YWxob3N0MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBANOcXjAyMipXbYP3DhkFt9uH" +
            "hc1k5WottUEwGH6xmUnqtZZSPrMLUl/9+IchxzXhRS9kxj4OySaXZzbCucdAO4UC" +
            "AQMwDQYJKoZIhvcNAQEFBQADQQCcL/7p4Wvmx/E7bvf8CPBxehsU+gxIE/LkQzZu" +
            "ceSEH4lYXdcT5cVxZxSgeANNrsiLOtGNkg78erW/2L6+JGng";
  var json = exports.x509ToJSON(b64);
  console.log(json);
};
