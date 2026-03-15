# Segurança

## Reportando Vulnerabilidades

Se você encontrar uma vulnerabilidade de segurança no AlertaWeb, por favor **NÃO** abra uma issue pública.

Envie um email para o mantenedor do repositório com:

1. Descrição da vulnerabilidade
2. Passos para reproduzir
3. Impacto potencial

Responderemos em até 48 horas.

## Política de API Keys

- API keys **nunca** devem ser commitadas no repositório
- O `.gitignore` já inclui arquivos comuns de secrets
- Todas as keys são armazenadas localmente via `chrome.storage.local`
- Nenhuma key transita por servidores nossos

## Permissões da Extensão

A extensão solicita as seguintes permissões:

| Permissão | Motivo |
|-----------|--------|
| `activeTab` | Acessar a aba ativa para análise |
| `storage` | Salvar configurações e histórico localmente |
| `scripting` | Injetar content script para extrair dados da página |
| `host_permissions (https/http)` | Fazer requests para APIs externas (Gemini, VirusTotal, etc.) |

Nenhuma permissão desnecessária é solicitada.
