KEY_SIZE = 2048
PRIVATE_KEY = ./test/private.pem
PUBLIC_KEY = ./test/public.pem

all: test

test: node_modules
	npm run test

lint: node_modules
	npm run lint

node_modules: package.json
	npm i

clean:
	rm -rf node_modules
	#rm -f $(PRIVATE_KEY) $(PUBLIC_KEY)

keys: $(PRIVATE_KEY) $(PUBLIC_KEY)

$(PRIVATE_KEY):
	openssl genpkey -algorithm RSA -out $(PRIVATE_KEY) -pkeyopt rsa_keygen_bits:$(KEY_SIZE)
	@echo "Generated private key: $(PRIVATE_KEY)"

$(PUBLIC_KEY): $(PRIVATE_KEY)
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY)
	@echo "Generated public key: $(PUBLIC_KEY)"

.PHONY: all keys clean

.PHONY: test install clean lint