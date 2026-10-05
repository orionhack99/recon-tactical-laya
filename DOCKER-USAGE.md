# Como usar com Docker

## Passo 1: Build
```bash
cd /home/user/tools/recon-ai-llama-cpp/recon-llama-laya
docker build -t recon-laya:latest .
```

## Passo 2: Criar diretório de saída
```bash
mkdir -p outputs
```

## Exemplos de uso

### 1) Triagem completa de domínio
```bash
docker run --rm --network host \
  -v $(pwd)/outputs:/app/outputs \
  recon-laya:latest -d TARGET.com -oj outputs/TARGET.json -om outputs/TARGET.md 2>&1 | tail -20
```

### 2) Pipeline com lista de subdomínios
```bash
cat subdomains.txt | docker run --rm --network host -i \
  recon-laya:latest -oj outputs/results.json
```

### 3) Execução com docker-compose
```bash
docker-compose run --rm recon-laya -d TARGET.com -oj /tmp/recon-outputs/scan.json
```

**Dica:** O script já possui múltiplas fontes de coleta de subdomínios (crt.sh, CertSpotter, RapidDNS, HackerTarget, Anubis, OTX, etc.) e fará fallback automático caso alguma falhe.
