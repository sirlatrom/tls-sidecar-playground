#!/bin/bash -e

docker stack rm stack || true
# No --detach=false option to docker stack rm yet, so sleep a bit and hope the network and conainers are gone
sleep 5
docker volume rm -f stack_vault-data
docker stack deploy -c docker-compose.yml stack
docker run --rm --volume stack_vault-data:/data alpine sh -c 'chown 100:1000 -R /data'
docker service scale --detach=false stack_vault=1
vault_cid=$(docker service ps --filter desired-state=running --format '{{.Name}}.{{.ID}}' --no-trunc stack_vault)
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault auth $(<vault_token.secret)
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault mount pki
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/root/generate/internal common_name=root
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/roles/dumbserver allowed_domains=localhost,dumbserver allow_bare_domains=true
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/roles/outproxy allowed_domains=localhost,outproxy allow_bare_domains=true
docker service scale --detach=false stack_outproxy=3 stack_dumbserver=3

## Optionally:
## - Trust CA:
# sudo curl -o /usr/local/share/ca-certificates/local-vault.crt http://127.0.0.1:8200/v1/pki/ca/pem && sudo update-ca-certificates
## - or manually download http://127.0.0.1:8200/v1/pki/ca/pem and add to authorities in Chrome or Firefox or whatever browser you prefer

xdg-open http://localhost/howdy
docker service logs -f stack_outproxy
