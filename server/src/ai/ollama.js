// Talks to a local Ollama server. Scan data must never leave this machine, so a model URL
// that isn't on this computer is refused outright.

const LOOPBACK = ['127.0.0.1', 'localhost', '[::1]'];
// Loading the model into memory takes 30+ seconds on the first call; answering takes ~10.
const REQUEST_TIMEOUT_MS = 180_000;

export class AiUnavailableError extends Error {}

export function ollamaConfig(env = process.env) {
  const url = env.OLLAMA_URL || 'http://127.0.0.1:11434';
  const model = env.OLLAMA_MODEL || 'llama3.1:8b';
  let host;
  try {
    host = new URL(url).hostname;
  } catch {
    throw new Error(`OLLAMA_URL is not a valid URL: ${url}`);
  }
  if (!LOOPBACK.includes(host)) {
    throw new Error(`OLLAMA_URL must point at this computer (127.0.0.1 or localhost), not ${host}: scan data stays local`);
  }
  return { url: url.replace(/\/+$/, ''), model };
}

// Returns the reply text. `format` is a JSON schema the reply must follow (Ollama enforces it).
export function createOllamaChat({ url, model }) {
  async function chat(messages, { format, signal } = {}) {
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(`${url}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages,
          format,
          stream: false,
          // Same input, same answer: triage should be repeatable, and the eval comparable.
          options: { temperature: 0, num_ctx: 4096 },
        }),
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
    } catch (err) {
      if (signal?.aborted) throw err;
      if (timeout.aborted) throw new AiUnavailableError(`Ollama did not answer within ${REQUEST_TIMEOUT_MS / 1000} seconds`);
      throw new AiUnavailableError(`can't reach Ollama at ${url}: is it running? (${err.cause?.code ?? err.message})`);
    }
    const body = await res.json().catch(() => ({}));
    if (res.status === 404) throw new AiUnavailableError(`model ${model} is not installed: run "ollama pull ${model}"`);
    if (!res.ok) throw new AiUnavailableError(`Ollama error (HTTP ${res.status}): ${body.error ?? 'no details'}`);
    return body.message?.content ?? '';
  }
  chat.model = model;
  return chat;
}
