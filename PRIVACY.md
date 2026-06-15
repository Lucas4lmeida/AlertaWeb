# Política de Privacidade — AlertaWeb

**Última atualização:** Maio 2026

## Dados coletados

O AlertaWeb **não coleta, armazena ou transmite dados pessoais do usuário**. Todos os dados processados ficam exclusivamente no navegador do usuário.

### Dados processados localmente (nunca saem do navegador):
- URL e domínio da página sendo analisada
- Texto visível da página (para detecção de padrões de golpe)
- Links e formulários presentes na página
- Remetente e assunto de emails (quando o scanner de email está ativo)
- Histórico de análises realizadas
- Configurações e chaves de API do usuário

### Dados enviados para APIs externas (quando configuradas pelo usuário):
- **Google Gemini**: URL, título e trecho do texto da página para análise por IA
- **Google Safe Browsing**: URL da página para verificação contra lista negra
- **VirusTotal**: URL da página para verificação por antivírus
- **IP2WHOIS**: Domínio da página para consulta de informações de registro

Esses dados são enviados **somente** para as APIs que o próprio usuário configurou, usando as chaves de API fornecidas pelo usuário. Nenhum dado é enviado para servidores do AlertaWeb ou de terceiros não autorizados.

## Armazenamento

- Chaves de API: armazenadas em `chrome.storage.local` (criptografado pelo Chrome)
- Histórico de análises: armazenado em `chrome.storage.local`
- Nenhum cookie é utilizado
- Nenhum dado é armazenado em servidores externos

## Permissões

| Permissão | Motivo |
|-----------|--------|
| `activeTab` | Acessar a aba ativa para análise quando o usuário clica no botão |
| `storage` | Salvar configurações e histórico localmente |
| `scripting` | Injetar script de extração de dados na página ativa |
| `host_permissions` | Fazer chamadas às APIs externas configuradas |

## Contato

Para dúvidas sobre privacidade, abra uma issue no repositório do projeto no GitHub.

## Código aberto

O código-fonte completo do AlertaWeb é aberto e disponível para auditoria no GitHub.
