type=$1  # client or server
name=$2
curl -XPOST -H 'content-type:application/json' -d @${name}_req.json "localhost:8002/certificate/${type}?download=${name}.zip" -o ${name}.zip
unzip ${name}.zip
mv cert.pem ${name}.pem
mv cert.key ${name}.key
rm ${name}.zip
