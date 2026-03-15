# Changelog

Todas as mudanças notáveis do projeto são documentadas aqui.

## [1.0.0] — 2026-03-13

### Adicionado
- 8 camadas de análise paralela (URL, Conteúdo, WHOIS, Segurança, Formulários, Safe Browsing, VirusTotal, Gemini IA)
- Detecção de typosquatting contra 25+ marcas brasileiras e internacionais
- Detecção especializada de sites de apostas/BET falsos (16 padrões)
- Whitelist de 80+ domínios confiáveis (Google, Meta, bancos BR, gov.br, e-commerces)
- Detecção de plataformas UGC para evitar falsos positivos (WhatsApp, Gmail, Reddit, etc.)
- Integração com Google Gemini 3.1 Flash Lite (IA) com retry e fallback
- Integração com VirusTotal (70+ antivírus)
- Integração com Google Safe Browsing (lista negra)
- Integração com IP2WHOIS API v2 (verificação de domínio)
- Interface dark theme com score animado
- Histórico de análises com opção de limpar
- Botão "Reanalisar" que força nova análise (ignora cache)
- Botão "Reportar Site" (Google Safe Browsing)
- Algoritmo de pontuação com peak floor (evita diluição por módulos limpos)
- Detecção de formulários sensíveis (CPF, cartão, CVV, PIX, dados bancários)
- Detecção de scripts maliciosos, iframes ocultos, texto invisível
- Prompt otimizado para reduzir consumo de tokens da API Gemini

### Segurança
- API keys armazenadas apenas localmente
- Nenhum dado enviado para servidores próprios
- Código 100% aberto para auditoria
