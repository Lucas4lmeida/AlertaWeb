<p align="center">
  <img src="icons/icon128.png" alt="AlertaWeb" width="80" />
</p>

<h1 align="center">AlertaWeb</h1>
<p align="center">Extensão Chrome para detecção de golpes, fraudes e phishing em tempo real.</p>

<p align="center">
  <img src="https://img.shields.io/badge/manifest-v3-blue" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" />
</p>

---

## Instalação

```bash
git clone https://github.com/SEU_USUARIO/alertaweb.git
```

1. Acesse `chrome://extensions/`
2. Ative o **Modo do desenvolvedor**
3. Clique em **Carregar sem compactação** e selecione a pasta

## O que analisa

### Páginas web (8 verificações)

- **URL** — HTTPS, TLD suspeito, typosquatting
- **Conteúdo** — linguagem de urgência, promessas falsas, timers de pressão
- **BETs/Apostas** — padrões de golpes de apostas online
- **Domínio (WHOIS)** — idade, expiração, proprietário oculto
- **Segurança** — scripts maliciosos, iframes ocultos
- **Formulários** — campos sensíveis (CPF, cartão, PIX), envio externo
- **VirusTotal** — 70+ engines antivírus
- **IA (Gemini)** — análise inteligente contextual

Sites conhecidos (Google, WhatsApp, bancos, etc.) são reconhecidos automaticamente via whitelist.

### Emails (scanner automático)

Funciona no Gmail, Outlook.com, Outlook 365 e Yahoo Mail. Ao abrir um email, analisa automaticamente:

- **Link mismatch** — texto mostra um domínio, href aponta outro
- **Remetente suspeito** — typosquatting de marcas conhecidas (nubank, itau, etc.)
- **Linguagem de phishing** — "sua conta será bloqueada", "confirme seus dados", etc.
- **Anexos perigosos** — menções a .exe, .scr, .bat e outros
- **Urgência + dados sensíveis** — combinação clássica de phishing
- **Links perigosos** — encurtadores, IPs numéricos, cruzamento com Safe Browsing e VirusTotal
- **Tooltips nos links** — passe o mouse sobre qualquer link para ver o destino real

Mostra um banner no topo do email: verde (seguro), amarelo (atenção) ou vermelho (phishing).

## APIs (todas gratuitas)

| API | Finalidade | Link |
|-----|-----------|------|
| Gemini | Análise por IA | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| Safe Browsing | Lista negra Google | [console.cloud.google.com](https://console.cloud.google.com) |
| VirusTotal | 70+ antivírus | [virustotal.com](https://www.virustotal.com) |
| IP2WHOIS | Dados do domínio | [ip2whois.com](https://www.ip2whois.com) |

Configure clicando em ⚙️ na extensão. Funciona sem APIs (usando heurísticas locais).

## Score

| Score | Nível |
|-------|-------|
| 0-24 | Seguro |
| 25-49 | Baixo |
| 50-74 | Médio |
| 75-89 | Alto |
| 90-100 | Crítico |

## Estrutura

```
alertaweb/
├── manifest.json
├── background.js        # Motor de análise
├── content.js           # Extração de dados da página
├── email-scanner.js     # Scanner de emails (Gmail, Outlook, Yahoo)
├── email-scanner.css    # Estilos do scanner (banner, tooltips)
├── popup.html / .js     # Interface
├── styles.css
└── icons/
```

## Contribuindo

1. Fork → branch → commit → PR

## Licença

[MIT](LICENSE)
