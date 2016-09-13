var jx509 = require('./index.js');
var http = require('http');
var querystring = require('querystring');

function base64ToJSON(base64) {
  console.log('input: ' + base64);
  try {
    return jx509.x509ToJSON(base64);
  } catch (e) {
    console.log('error: ' + e);
    return JSON.stringify(e);
  }
}

var server = http.createServer(function(req, res) {
  if (req.method == 'POST') {
    var base64 = '';
    req.on('data', function(data) {
      base64 += data;
    });
    req.on('end', function() {
      res.writeHead(200, {'Content-Type': 'text/plain',
                          'Charset': 'utf-8',
                          'Access-Control-Allow-Origin': '*'});
      res.end(base64ToJSON(base64));
    });
  } else {
    console.log(req.url);
    var parsed = querystring.parse(req.url.slice(1));
    console.log(parsed);
    var base64 = querystring.parse(req.url.slice(1)).base64;
    res.writeHead(200, {'Content-Type': 'text/plain',
                        'Charset': 'utf-8',
                        'Access-Control-Allow-Origin': '*'});
    res.end(base64ToJSON(base64));
  }
});

server.listen(process.env.PORT || 8000);
