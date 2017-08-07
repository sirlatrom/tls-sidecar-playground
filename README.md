# mtls-stack
## Setup
```bash
cd ..
git clone https://github.com/sirlatrom/dumbserver
git clone https://github.com/sirlatrom/outproxy
echo -n '1234' > vault_token.secret
docker stack deploy -c mtls-stack/docker-compose.yml stack
docker run --rm --volume stack_vault-data:/data alpine sh -c 'chown 100:1000 -R /data'
docker service scale stack_vault=1
while ! docker service ps --filter desired-state=running --format '{{.Name}}.{{.ID}}' --no-trunc stack_vault | xargs -I % docker ps --filter name=% --filter health=healthy --format '{{.Names}}' | xargs docker inspect &> /dev/null
do
    echo "Waiting for vault to be healthy"
    sleep 1
done
vault_cid=$(docker service ps --filter desired-state=running --format '{{.Name}}.{{.ID}}' --no-trunc stack_vault)
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault auth 1234
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault mount pki
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/root/generate/internal common_name=root
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/roles/dumbserver allowed_domains=localhost,dumbserver allow_bare_domains=true
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${vault_cid} vault write pki/roles/outproxy allowed_domains=localhost,outproxy allow_bare_domains=true
```
