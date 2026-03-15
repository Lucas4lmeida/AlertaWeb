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

A extensão executa 8 verificações em paralelo ao clicar em "Analisar":

- **URL** — HTTPS, TLD suspeito, typosquatting
- **Conteúdo** — linguagem de urgência, promessas falsas, timers de pressão
- **BETs/Apostas** — padrões de golpes de apostas online
- **Domínio (WHOIS)** — idade, expiração, proprietário oculto
- **Segurança** — scripts maliciosos, iframes ocultos
- **Formulários** — campos sensíveis (CPF, cartão, PIX), envio externo
- **VirusTotal** — 70+ engines antivírus
- **IA (Gemini)** — análise inteligente contextual

Sites conhecidos (Google, WhatsApp, bancos, etc.) são reconhecidos automaticamente via whitelist.

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

APIs não configuradas são excluídas do cálculo. O score final nunca fica abaixo de 70% do módulo mais alto (evita diluição).

## Estrutura

```
alertaweb/
├── manifest.json
├── background.js      # Motor de análise
├── content.js         # Extração de dados da página
├── popup.html / .js   # Interface
├── styles.css
└── icons/
```

## Contribuindo

1. Fork → branch → commit → PR

## Licença

[MIT](LICENSE)
