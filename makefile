IN:=in.tgz
SIGNED:=signed/$(IN)
SIGNATURE:=$(IN).sig
DIGEST:=$(IN).digest

all: tgz-verify id_rsa.pub.der $(SIGNED)
	LD_LIBRARY_PATH=../INSTALL/lib ./tgz-verify $(SIGNED) id_rsa.pub.der

tgz-verify: tgz-verify.cpp id_rsa.pub.der
	g++ -pedantic -Werror=nonnull -Wextra -Wnarrowing -Wall -Werror -DDEBUG -O0 -g -L../INSTALL/lib -laxtls -I../INSTALL/include $< -o $@

privatekey.pem:
	# create the OpenSSL key pair
	openssl genrsa -out privatekey.pem 2048
	openssl rsa -in privatekey.pem -text -noout

publickey.pem: privatekey.pem
	# split the id_rsa pair into sepparate files for private/public keys
	openssl rsa -in privatekey.pem -pubout -out publickey.pem

$(DIGEST): $(IN)
	openssl dgst -sha256 -out $(DIGEST) $(IN)

$(SIGNATURE): privatekey.pem $(DIGEST)
	openssl rsautl -sign -in $(DIGEST) -inkey privatekey.pem -out $(SIGNATURE)

$(SIGNED): $(IN) $(SIGNATURE)
	mkdir -p signed/
	cp $(IN) $(SIGNED)
	echo -n "PKCSSIG($(IN))= " >> $@
	cat $<.sig >> $@

verify: clean publickey.pem $(SIGNATURE)
	openssl rsautl -verify -in $(SIGNATURE) -out D-$(DIGEST) -inkey publickey.pem -pubin
	diff $(DIGEST) D-$(DIGEST)
	openssl dgst -sha256 -verify publickey.pem -signature $(SIGNATURE) $(IN)

id_rsa.pub.der: publickey.pem
	grep -v -- ----- publickey.pem | tr -d '\n'  | base64 -d > $@

.PHONY: clean info
clean:
	rm -rf signed *.b64 *.der *.pem *.digest *.sig tgz-verify

info: publickey.pem
	grep -v -- ----- publickey.pem | tr -d '\n'  | base64 -d | openssl asn1parse -inform DER -i
	grep -v -- ----- publickey.pem | base64 -d | openssl asn1parse -inform DER -i -strparse 18
