var forge = require('node-forge');
var atob = require('atob');
var fs = require('fs');

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
  var hash = digest.digest()
                   .toHex()
                   .toUpperCase()
                   .replace(/([A-F0-9]{2})/g, "$1:");
  return hash.substring(0, hash.length - 1);
}

function oidToString(forgeOid) {
  if (forgeOid in forge.pki.oids) {
    return forge.pki.oids[forgeOid];
  }
  return forgeOid;
}

function findExtension(cert, extensionName) {
  var result = cert.extensions.filter(function(extension) {
    return (extension.name == extensionName);
  });
  return result.length > 0 ? result[0] : null;
}

function findExtensionByOID(cert, oid) {
  var result = cert.extensions.filter(function(extension) {
    return (extension.id == oid);
  });
  return result.length > 0 ? result[0] : null;
}

function formatBasicConstraints(cert) {
  var extension = findExtension(cert, "basicConstraints");
  if (!extension) {
    return "(not present)";
  }
  if (!extension.cA) {
    return "cA: false";
  }
  if ("pathLenConstraint" in extension) {
    return "cA: true, pathLenConstraint: " + extension.pathLenConstraint;
  }
  return "cA: true";
}

function formatKeyUsage(cert) {
  var extension = findExtension(cert, "keyUsage");
  if (!extension) {
    return "(not present)";
  }
  var output = "";
  ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
   "keyAgreement", "keyCertSign", "cRLSign"].forEach(function(keyUsage) {
     if (extension[keyUsage]) {
       output += (output ? ", " : "") + keyUsage;
     }
   });
  return output;
}

function formatExtKeyUsage(cert) {
  var extension = findExtension(cert, "extKeyUsage");
  if (!extension) {
    return "(not present)";
  }
  var output = "";
  // todo: include OCSPSigning
  ["serverAuth", "clientAuth", "codeSigning", "emailProtection",
   "timeStamping"].forEach(function(keyUsage) {
     if (extension[keyUsage]) {
       output += (output ? ", " : "") + keyUsage;
     }
   });
  return output;
}

function formatAuthorityInformationAccess(cert) {
  var extension = findExtensionByOID(cert, "1.3.6.1.5.5.7.1.1");
  if (!extension) {
    return "(not present)";
  }
  var format = {
    name: 'AccessDescriptions',
    tagClass: forge.asn1.Class.UNIVERSAL,
    type: forge.asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'AccessDescriptions',
  };
  var capture = {};
  var errors = [];
  if (!forge.asn1.validate(forge.asn1.fromDer(extension.value), format,
                           capture, errors)) {
    return "(could not parse)";
  }
  var output = "";
  var descriptions = capture.AccessDescriptions.value;
  descriptions.forEach(function(description) {
    var type = forge.asn1.derToOid(description.value[0].value);
    var value = description.value[1].value;
    if (type == "1.3.6.1.5.5.7.48.1") { // id-ad-ocsp
      output += (output ? ", " : "") + value;
    }
  });
  return output;
}

function formatCRLDistributionPoints(cert) {
  var extension = findExtension(cert, "cRLDistributionPoints");
  if (!extension) {
    return "(not present)";
  }
  var format = {
    name: 'CRLDistributionPoints',
    tagClass: forge.asn1.Class.UNIVERSAL,
    type: forge.asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'CRLDistributionPoints',
  };
  var capture = {};
  var errors = [];
  if (!forge.asn1.validate(forge.asn1.fromDer(extension.value), format,
                           capture, errors)) {
    return "(could not parse)";
  }
  var output = "";
  var distributionPoints = capture.CRLDistributionPoints.value;
  distributionPoints.forEach(function(distributionPoint) {
    if (distributionPoint.value.length > 0 &&
        distributionPoint.value[0].tagClass == 0x80 &&
        distributionPoint.value[0].type == 0) {
      var distributionPointName = distributionPoint.value[0];
      if (distributionPointName.value.length > 0 &&
          distributionPointName.value[0].tagClass == 0x80 &&
          distributionPointName.value[0].type == 0) {
        var generalNames = distributionPointName.value[0].value;
        generalNames.forEach(function(generalName) {
          if (generalName.tagClass == 0x80 &&
              (generalName.type == 1 || // rfc822Name
               generalName.type == 2 || // dNSName
               generalName.type == 6)) { // URI
            output += (output ? ", " : "") + generalName.value;
          }
        });
      }
    }
  });
  return output;
}

function formatPublicKey(cert) {
  if (cert.publicKey.n) {
    return "RSA " + cert.publicKey.n.bitLength() + " bits";
  }
  if (cert.publicKey.curve) {
    return "EC " + oidToString(cert.publicKey.curve);
  }
  return "unknown key type";
}

// Finds all dNSName and iPAddress entries and returns:
// {
//    permitted: [entries],
//    excluded: [entries]
// }
// where an entry is:
// {
//   type: <"dNSName"|"iPAddress">
// }
function searchNameConstraints(extensionValue) {
  var nameConstraints = forge.asn1.fromDer(extensionValue);
  var permittedOut = [];
  var excludedOut = [];
  for (var i in nameConstraints.value) {
    var subtree = nameConstraints.value[i];
    var outlist = subtree.type == 0 ? permittedOut : excludedOut;
    for (var i = 0; i < subtree.value.length; i++) {
      var entry = subtree.value[i].value[0];
      if (entry.type == 2) { // dNSName
        outlist.push({type: "dNSName"});
      } else if (entry.type == 7) { // iPAddress
        outlist.push({type: "iPAddress"});
      }
    }
  }
  return { permitted: permittedOut, excluded: excludedOut };
}

// A certificate is technically constrained if it has the extendedKeyUsage
// extension that does not contain anyExtendedKeyUsage and either does not
// contain the serverAuth extended key usage or has the nameConstraints
// extension with both dNSName and iPAddress entries.
function determineIfTechnicallyConstrained(cert) {
  var eku = findExtension(cert, "extKeyUsage");
  if (!eku) {
    return "no";
  }
  // id-ce OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 29 }
  // id-ce-extKeyUsage OBJECT IDENTIFIER ::= {id-ce 37}
  // anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
  if ("2.5.29.37.0" in eku) {
    return "no";
  }
  if (!("serverAuth" in eku)) {
    return "yes";
  }
  var nameConstraints = findExtension(cert, "nameConstraints");
  if (!nameConstraints) {
    return "no";
  }
  var constraints = searchNameConstraints(nameConstraints.value);
  var hasDNSName = constraints.permitted.some(function(entry) { return entry.type == "dNSName"; }) ||
                   constraints.excluded.some(function(entry) { return entry.type == "dNSName"; });
  var hasIPAddress = constraints.permitted.some(function(entry) { return entry.type == "iPAddress"; }) ||
                     constraints.excluded.some(function(entry) { return entry.type == "iPAddress"; });
  if (hasDNSName && hasIPAddress) {
    return "yes";
  }
  return "no";
}

exports.x509ToJSON = function(base64) {
  var cert = null;
  var der = null;
  try {
    cert = forge.pki.certificateFromPem(base64);
    der = atob(base64.replace(/-----BEGIN CERTIFICATE-----/, "")
                     .replace(/-----END CERTIFICATE-----/, "")
                     .replace(/[\r\n]/g, ""));
  } catch (e) {
  }
  if (!cert) {
    // Try again with the PEM header/footer
    var pem = base64ToPEM(base64);
    cert = forge.pki.certificateFromPem(pem);
    der = atob(base64);
  }
  var result = {
    issuerCN: getDNField(cert.issuer, 'CN'),
    issuerOU: getDNField(cert.issuer, 'OU'),
    issuerO: getDNField(cert.issuer, 'O'),
    issuerC: getDNField(cert.issuer, 'C'),
    subjectCN: getDNField(cert.subject, 'CN'),
    subjectOU: getDNField(cert.subject, 'OU'),
    subjectO: getDNField(cert.subject, 'O'),
    subjectC: getDNField(cert.subject, 'C'),
    sha1Fingerprint: hashBytes(forge.md.sha1, der),
    sha256Fingerprint: hashBytes(forge.md.sha256, der),
    notBefore: cert.validity.notBefore.toUTCString(),
    notAfter: cert.validity.notAfter.toUTCString(),
    version: cert.version + 1,
    serialNumber: cert.serialNumber,
    signatureAlgorithm: oidToString(cert.signatureOid),
    publicKey: formatPublicKey(cert),
    basicConstraints: formatBasicConstraints(cert),
    keyUsage: formatKeyUsage(cert),
    extKeyUsage: formatExtKeyUsage(cert),
    ocsp: formatAuthorityInformationAccess(cert),
    crl: formatCRLDistributionPoints(cert),
    technicallyConstrained: determineIfTechnicallyConstrained(cert),
  };
  return JSON.stringify(result);
};

function readCert(filename) {
  var data = fs.readFileSync(filename);
  return data.toString().replace(/[\r\n]/g, "")
                        .replace(/-----BEGIN CERTIFICATE-----/, "")
                        .replace(/-----END CERTIFICATE-----/, "");
}

function testField(filename, field, expectedValue) {
  var data = fs.readFileSync(filename).toString();
  var json = exports.x509ToJSON(data);
  var parsed = JSON.parse(json);
  if (parsed[field] != expectedValue) {
    throw filename + " failed. Expected '" + expectedValue + "' got '" + parsed[field] + "'";
  } else {
    console.log(filename + " passed.");
  }
}

exports.powerOnSelfTest = function() {
  /*
  var b64 = "MIIGLTCCBRWgAwIBAgIIGN2Hrh9LtmwwDQYJKoZIhvcNAQEFBQAwgZUxCzAJBgNV" +
            "BAYTAkdSMUQwQgYDVQQKEztIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2gg" +
            "SW5zdGl0dXRpb25zIENlcnQuIEF1dGhvcml0eTFAMD4GA1UEAxM3SGVsbGVuaWMg" +
            "QWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0aW9ucyBSb290Q0EgMjAxMTAe" +
            "Fw0xMzEyMTIxNjEwNDRaFw0yMTEyMTAxNjEwNDRaMIGDMQswCQYDVQQGEwJHUjFE" +
            "MEIGA1UEChM7SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0" +
            "aW9ucyBDZXJ0LiBBdXRob3JpdHkxLjAsBgNVBAMTJVVuaXZlcnNpdHkgb2YgV2Vz" +
            "dGVybiBNYWNlZG9uaWEgQ0EgUjIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
            "AoIBAQCqqtxNIEnRXNvyq7JvVWFea3yAqiun5r/Ehsh9Ln+p2D2d1DgpD7bme0oj" +
            "k49qe/MYadL8bcAveCPRtX3m8N1dBz1IaHcr1cewUV/ptBk6KwTrrHt5HsE4ou1T" +
            "7mS719nD5L+a/O5WZstzbQTuhQ4q0QknCyTwS+RW2XULzGLmGHSc1BMIND/3UNej" +
            "aYn+HIwx5VZwnLqyEYYOG/CtnClKpcqx5D20lUL8Xn8N2jZcWAgRbxs/2io+M+mf" +
            "agP/kph7cvRzsjVmnMjqgIEO2O5CzT6xegkx9qzHYMS0iJU3CtyqVgQTiP4PoDvB" +
            "kYPqTBLZ+TEQS4DXP5KgfIJt88eRAgMBAAGjggKPMIICizAPBgNVHRMBAf8EBTAD" +
            "AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUpiRDZErEZqADQ9gZeIRbDUwd" +
            "6zkwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybHYxLmhhcmljYS5nci9IYXJp" +
            "Y2FSb290Q0EyMDExL2NybHYxLmRlci5jcmwwHwYDVR0jBBgwFoAUppFC/RNhSiOe" +
            "CKQp5dgTBCPuQSUwbgYIKwYBBQUHAQEEYjBgMCEGCCsGAQUFBzABhhVodHRwOi8v" +
            "b2NzcC5oYXJpY2EuZ3IwOwYIKwYBBQUHMAKGL2h0dHA6Ly93d3cuaGFyaWNhLmdy" +
            "L2NlcnRzL0hhcmljYVJvb3RDQTIwMTEucGVtMIIBPwYDVR0gBIIBNjCCATIwggEu" +
            "BgwrBgEEAYHPEQEAAgcwggEcMDIGCCsGAQUFBwIBFiZodHRwOi8vd3d3Lmhhcmlj" +
            "YS5nci9kb2N1bWVudHMvQ1BTLnBocDCB5QYIKwYBBQUHAgIwgdgwShZDSGVsbGVu" +
            "aWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0aW9ucyBDZXJ0aWZpY2F0" +
            "aW9uIEF1dGhvcml0eTADAgEBGoGJVGhpcyBjZXJ0aWZpY2F0ZSBpcyBzdWJqZWN0" +
            "IHRvIEdyZWVrIGxhd3MgYW5kIG91ciBDUFMuIFRoaXMgQ2VydGlmaWNhdGUgbXVz" +
            "dCBvbmx5IGJlIHVzZWQgZm9yIGFjYWRlbWljLCByZXNlYXJjaCBvciBlZHVjYXRp" +
            "b25hbCBwdXJwb3Nlcy4wLQYDVR0eBCYwJKAiMAmCB3Vvd20uZ3IwCYEHdW93bS5n" +
            "cjAKgQgudW93bS5ncjANBgkqhkiG9w0BAQUFAAOCAQEAZMPHko1eArdqJTtTtWmJ" +
            "TMPtj9PWXFlKdq+4YMh0tA4WRlC0YgH6qt6PBx/Ms2bqIqaw+67cHl1sFI8waQep" +
            "ZlMr3lDDyNL1YUltPMbpTml0XcmzYDiI0FjGEM0wmyjYpZl7QdLleyoZnlaKE+MA" +
            "ddZ7OXxNF20St70U8YhHVWO28p/btzaxxB7zZPdycSR0se88WA/u8uGfIIiSzFwL" +
            "Av60uayq9P+G4tvojJSYIzRv7vEGFJYp8sYON/XJUWXCctxiJ+Tury9WueBkps/c" +
            "I04ez4fFSCGAYhcoXmPB7pBpBeGbq+ihgWQisMCglR2YvtpIG8uN9Qv7uXEPONme" +
            "GQ==";
  */
  /*
  var b64 = "MIIGwjCCBaqgAwIBAgIQCgTfIXRdTSuM6jNyBQBQ6TANBgkqhkiG9w0BAQUFADBl" +
            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" +
            "d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv" +
            "b3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMjExMTEwMDAwMDAwWjBiMQswCQYDVQQG" +
            "EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl" +
            "cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTEwggEiMA0G" +
            "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDogi2Z+crCQpWlgHNAcNKeVlRcqcTS" +
            "QQaPyTP8TUWRXIGf7Syc+BZZ3561JBXCmLm0d0ncicQK2q/LXmvtrbBxMevPOkAM" +
            "Rk2T7It6NggDqww0/hhJgv7HxzFIgHweog+SDlDJxofrNj/YMMP/pvf7os1vcyP+" +
            "rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds97bFBo+0/vtuVSMTuHrPyvAwrmdDGXRJC" +
            "geGDboJzPyZLFJCuWWYKxI2+0s4Grq2Eb0iEm09AufFM8q+Y+/bOQF1c9qjxL6/s" +
            "iSLyaxhlscFzrdfx2M8eCnRcQrhofrfVdwonVnwPYqQ/MhRglf0HBKIJAgMBAAGj" +
            "ggNvMIIDazAOBgNVHQ8BAf8EBAMCAYYwOwYDVR0lBDQwMgYIKwYBBQUHAwEGCCsG" +
            "AQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQGCCsGAQUFBwMIMIIBxgYDVR0gBIIB" +
            "vTCCAbkwggG1BgtghkgBhv1sAQMABDCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93" +
            "d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEF" +
            "BQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBl" +
            "AHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBj" +
            "AGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0" +
            "ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAg" +
            "AFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABp" +
            "AG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBu" +
            "AGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBm" +
            "AGUAcgBlAG4AYwBlAC4wDwYDVR0TAQH/BAUwAwEB/zB9BggrBgEFBQcBAQRxMG8w" +
            "JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBHBggrBgEFBQcw" +
            "AoY7aHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ0FDZXJ0cy9EaWdpQ2VydEFzc3Vy" +
            "ZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmwzLmRp" +
            "Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0" +
            "dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j" +
            "cmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0rZwLNMB8GA1UdIwQYMBaAFEXr" +
            "oq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IBAQCEYU5BHrh2BCq1" +
            "tu+P8lWFuV1W/gqY5uS9ZYp9QCnT/LFdRf06uCpbM0skXM25tORzrWFddq10M4pm" +
            "1SOvTB9ybkXZdUC7ojvPjUkvwEGw4imjUThDUJkUrDMGNWKJfXepUgflbCBXtoG6" +
            "b7yzwpTtdgKA2XzOhagc7MdDSkuxV89yzt/1JTzLIk/9n1LRN8sIuzg+4NU+b3kJ" +
            "rVt8MbN3NcPkY/loCpgH50Y4d4TSPpe8CqCorCVPRG6R4dJar2vvMByNo0RCsxCL" +
            "I/rX5jV0N6zP66tYH8mII/821AfqNGpH6p2VbJ4pT1Pt4yuVIE4qz5ZgevgsgPCV" +
            "Us4ploFi";
  var b64 = "MIIBXjCCAQOgAwIBAgIUf/ho98uapsYOR2WOtV526gbsI1kwCgYIKoZIzj0EAwIw" +
            "HTEbMBkGA1UEAwwScm9vdF9zZWNwMjU2cjFfMjU2MCIYDzIwMTMwNjMwMDAwMDAw" +
            "WhgPMjAxNjA3MDQwMDAwMDBaMB0xGzAZBgNVBAMMEnJvb3Rfc2VjcDI1NnIxXzI1" +
            "NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE+/u7th4Pj5saYKWayHBOLsBQtC" +
            "Pjz3LpI/LE95S0VcKmnSM0VsNsQRnQcG4A7tyNGTkNeZG3stB6ME6qBKpsCjHTAb" +
            "MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQDb" +
            "bszMB0wjid7NagmYoJ2Oano6EIVhihlge9Z7Qi+3YgIhAPEJx2Ac3OklePzVLiQW" +
            "FRYPss5YQVGRHL1UZYWYKDw5";
  var json = exports.x509ToJSON(b64);
  console.log(json);
  */
  testField("tc-NameConstraints-no-iPAddress.pem", "technicallyConstrained", "no");
  testField("tc-anyEKU.pem", "technicallyConstrained", "no");
  testField("tc-noEKU.pem", "technicallyConstrained", "no");
  testField("tc-noNameConstraints.pem", "technicallyConstrained", "no");
  testField("tc-noServerAuth.pem", "technicallyConstrained", "yes");
  testField("tc-properlyConstrained.pem", "technicallyConstrained", "yes");
  testField("tc-properlyConstrained-excluded.pem", "technicallyConstrained", "yes");
};
