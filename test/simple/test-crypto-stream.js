// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var common = require('../common');
var assert = require('assert');
var path = require('path');
var fs = require('fs');

try {
  var crypto = require('crypto');
} catch (e) {
  console.log('Not compiled with OPENSSL support.');
  process.exit();
}


var filePath = path.join(common.fixturesDir, 'person.jpg');
var referenceBuffer = fs.readFileSync(filePath);
var readStreamOptions = {
  flags: 'r',
  bufferSize: 1024
};


var testHash = function(hashName, hashEncoding) {
  // create reference digest
  var hashBuffer = crypto.createHash(hashName);
  hashBuffer.update(referenceBuffer);
  var digestBuffer = hashBuffer.digest(hashEncoding || 'buffer');

  // create digest from stream
  var stream = fs.createReadStream(filePath, readStreamOptions);
  var hashStream = crypto.createHashStream(hashName, { outputEncoding: hashEncoding });

  stream.pipe(hashStream);

  hashStream.on('data', function(data) {
    assert.deepEqual(data, digestBuffer);
  });
};


testHash('sha1', null);
testHash('sha1', 'hex');
testHash('sha1', 'base64');


var testHmac = function(hashName, hashEncoding) {
  // create reference digest
  var hashBuffer = crypto.createHash(hashName);
  hashBuffer.update(referenceBuffer);
  var digestBuffer = hashBuffer.digest(hashEncoding || 'buffer');

  // create digest from stream
  var stream = fs.createReadStream(filePath, readStreamOptions);
  var hashStream = crypto.createHashStream(hashName, { outputEncoding: hashEncoding });

  stream.pipe(hashStream);

  hashStream.on('data', function(data) {
    assert.deepEqual(data, digestBuffer);
  });
};


testHash('md5', null);
testHash('md5', 'hex');
testHash('md5', 'base64');

testHash('sha1', null);
testHash('sha1', 'hex');
testHash('sha1', 'base64');

testHash('sha256', null);
testHash('sha256', 'hex');
testHash('sha256', 'base64');
