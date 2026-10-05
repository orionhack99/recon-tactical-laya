# Recon Laya - Docker Setup

## Pré-requisitos

- Docker instalado
- Docker Compose instalado

## Build e Execução

### 1. Build da imagem

```bash
docker build -t recon-laya .
```

### 2. Executando com docker run

#### Usando domínio como alvo
```bash
docker run --rm -it --network host \
  -v $(pwd)/outputs:/tmp/outputs \
  recon-laya -d example.com
```

#### Usando stdin (pipeline)
```bash
echo "subdomain.example.com" | docker run --rm -it --network host -i \
  recon-laya
```

#### Gerando relatórios JSON/Markdown
```bash
docker run --rm -it --network host \
  -v $(pwd)/outputs:/tmp/outputs \
  recon-laya -d example.com \
  -oj /tmp/outputs/report.json \
  -om /tmp/outputs/report.md
```

### 3. Executando com docker-compose

```bash
# Exibir ajuda
docker-compose run --rm recon-laya

# Executar com domínio
docker-compose run --rm recon-laya -d example.com -oj /tmp/recon-outputs/output.json
```

## Volumes

- `./:/app` - Monta o código fonte (útil para desenvolvimento)
- `/tmp/recon-outputs:/tmp/recon-outputs` - Diretório para relatórios gerados

## Notas

- `network_mode: host` é utilizado para acesso direto à rede durante o reconnaissance (necessário para consultas a crt.sh, APIs externas, etc.)
- O modelo GGUF (`Laya-BF16.gguf`) e assinaturas Wappalyzer são carregados na inicialização (primeira execução pode demorar um pouco devido ao preload)
- Para reduzir ruído nos logs, redirecione stderr se necessário: `docker run ... 2>/dev/null`
