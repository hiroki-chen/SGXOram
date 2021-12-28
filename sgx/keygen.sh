mypass="1234"

echo Generate server key:
openssl genrsa -passout pass:$mypass -des3 -out sslcred.key 4096

echo Generate server signing request:
openssl req -passin pass:$mypass -new -key sslcred.key -out sslcred.csr -subj  "/C=CN/ST=TJ/L=TianJin/O=Nankai University/OU=Lab627/CN=localhost"

echo Self-sign server certificate:
openssl x509 -req -passin pass:$mypass -days 365 -in sslcred.csr -signkey sslcred.key -set_serial 01 -out sslcred.crt

echo Remove passphrase from server key:
openssl rsa -passin pass:$mypass -in sslcred.key -out sslcred.key

rm sslcred.csr

# Move them to the key folder.
mv *.crt *.key $(pwd)/key