# Monitor Server

App web em Python para gerenciar o servidor (porta 5050).

## Rodar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Acesse: `http://localhost:5050`

## Variáveis de ambiente

- `BROWSE_ROOT`: raiz de navegação de arquivos (padrão `/home`).
- `MAX_UPLOAD_MB`: limite de upload (padrão 100).
- `ADMIN_TOKEN`: se definido, exige token via header `X-Admin-Token` ou query `?token=...`.


resset do serviço 

sudo systemctl restart monitor-server