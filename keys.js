// ============================================================================
// AlertaWeb — Chaves de API embutidas (temporárias para demonstração)
// Após a apresentação, limpe os valores abaixo (deixe strings vazias)
// ============================================================================

const EMBEDDED_KEYS = {
  gemini: 'ACUfEycYFCcnBkoGb2wcNiQOKjgEMFoCc3twIQM6LAcVChRGX0Z3',
  safeBrowsing: 'ACUfEycYExQLQUFffHICJAgTOwMjVlUAeEFzGgI+Pg0bJghHcgoG',
  virusTotal: 'dQgHE0JSYwRbBQEHBiRZVkYQWW5dAAtSAw8iWAATRlVjUlABBFEEdwpdRRIFYVYHC1YFD3JVXBAQBGJRVVYFBw==',
  whois: 'BVgnNkRTYVwjcHQHBHBYUEpFI24nVnMIAHVwVVJGTVM='
};

const _K = 'AlertaWeb2026';
function _decode(encoded) {
  if (!encoded) return '';
  try {
    const raw = atob(encoded);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
      result += String.fromCharCode(raw.charCodeAt(i) ^ _K.charCodeAt(i % _K.length));
    }
    return result;
  } catch { return ''; }
}

function getEmbeddedKeys() {
  return {
    gemini: _decode(EMBEDDED_KEYS.gemini),
    safeBrowsing: _decode(EMBEDDED_KEYS.safeBrowsing),
    virusTotal: _decode(EMBEDDED_KEYS.virusTotal),
    whois: _decode(EMBEDDED_KEYS.whois)
  };
}
