Java.perform(function()
{
    console.log("[*] Starting API tracing...");

// Trace
HTTP
requests
try {
var OkHttpClient = Java.use('okhttp3.OkHttpClient');
OkHttpClient.newCall.implementation = function(request) {
var url = request.url().toString();
var method = request.method();

send({
type: 'http_request',
url: url,
method: method,
timestamp: new
Date().toISOString()
});

console.log(`[HTTP] ${method}: ${url}
`);
return this.newCall(request);
};
} catch(e)
{}

// Trace
file
operations
try {
var File = Java.use('java.io.File');

File.$init.overload('java.lang.String').implementation = function(path) {
send({
type: 'file_access',
path: path,
operation: 'open',
timestamp: new
Date().toISOString()
});
return this.$init(path);
};

File.delete.implementation = function()
{
send({
    type: 'file_access',
    path: this.getPath(),
    operation: 'delete',
    timestamp: new Date().toISOString()
});
return this.delete();
};
} catch(e)
{}

// Trace
crypto
operations
try {
var Cipher = Java.use('javax.crypto.Cipher');

Cipher.doFinal.overload('[B').implementation = function(input) {
send({
type: 'crypto',
operation: 'encrypt/decrypt',
algorithm: this.getAlgorithm(),
input_length: input.length,
timestamp: new
Date().toISOString()
});
return this.doFinal(input);
};
} catch(e)
{}
});