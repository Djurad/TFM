const { spawn } = require('child_process');

function normalizeTimeout(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function appendBounded(current, chunk, maxBytes) {
  const next = current + chunk;
  if (!maxBytes || next.length <= maxBytes) return next;
  return next.slice(next.length - maxBytes);
}

function createLineEmitter(callback) {
  let buffer = '';
  return {
    push(chunk) {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      lines.map(line => line.trim()).filter(Boolean).forEach(callback);
    },
    flush() {
      const line = buffer.trim();
      buffer = '';
      if (line) callback(line);
    }
  };
}

function runToolControlled(options = {}) {
  const {
    name,
    command,
    args = [],
    input = '',
    cwd = process.cwd(),
    env = process.env,
    timeoutMs = null,
    idleTimeoutMs = null,
    killOnIdle = false,
    maxOutputBytes = 1024 * 1024 * 20,
    signal,
    onStdoutLine = () => {},
    onStderrLine = () => {},
    onProgress = () => {},
    onStart = () => {},
    onEnd = () => {},
    progressIntervalMs = Number(process.env.TOOL_PROGRESS_INTERVAL_MS || 30000),
    allowLongRunning = true,
    nonInteractive = true
  } = options;

  return new Promise((resolve, reject) => {
    if (!command) {
      reject(new Error('Comando no definido.'));
      return;
    }

    const startedAt = Date.now();
    const timeout = normalizeTimeout(timeoutMs);
    const idleTimeout = normalizeTimeout(idleTimeoutMs);
    let stdout = '';
    let stderr = '';
    let lastOutput = '';
    let lastOutputAt = startedAt;
    let timedOut = false;
    let idleTimedOut = false;
    let cancelled = false;
    let settled = false;
    let closed = false;
    let timeoutId = null;
    let idleInterval = null;
    let progressInterval = null;

    const emitProgress = extra => {
      onProgress({
        name,
        command,
        args,
        durationMs: Date.now() - startedAt,
        lastOutput,
        lastOutputAt,
        timeoutMs: timeout,
        idleTimeoutMs: idleTimeout,
        allowLongRunning,
        nonInteractive,
        ...extra
      });
    };

    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const killChild = reason => {
      if (closed) return;
      try {
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!closed) {
            try {
              child.kill('SIGKILL');
            } catch {
              // El proceso puede haber salido entre SIGTERM y SIGKILL.
            }
          }
        }, 2500).unref?.();
      } catch {
        // Nada util que hacer si el proceso ya no existe.
      }
      emitProgress({ event: 'killing', reason });
    };

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      if (idleInterval) clearInterval(idleInterval);
      if (progressInterval) clearInterval(progressInterval);
      if (signal) signal.removeEventListener?.('abort', onAbort);
    };

    const onAbort = () => {
      cancelled = true;
      killChild('cancelled');
    };

    const onLine = (stream, line) => {
      lastOutput = line;
      lastOutputAt = Date.now();
      if (stream === 'stdout') onStdoutLine(line);
      else onStderrLine(line);
      emitProgress({ event: 'output', stream, line });
    };

    const stdoutLines = createLineEmitter(line => onLine('stdout', line));
    const stderrLines = createLineEmitter(line => onLine('stderr', line));

    onStart({ name, command, args, startedAt, timeoutMs: timeout, idleTimeoutMs: idleTimeout });
    emitProgress({ event: 'start' });

    if (signal?.aborted) {
      onAbort();
    } else if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }

    if (timeout) {
      timeoutId = setTimeout(() => {
        timedOut = true;
        killChild('timeout');
      }, timeout);
    }

    if (idleTimeout) {
      idleInterval = setInterval(() => {
        const idleFor = Date.now() - lastOutputAt;
        if (idleFor < idleTimeout) return;
        emitProgress({ event: 'idle', idleForMs: idleFor });
        if (killOnIdle) {
          idleTimedOut = true;
          killChild('idle-timeout');
        }
      }, Math.min(idleTimeout, 30000));
    }

    if (progressIntervalMs > 0) {
      progressInterval = setInterval(() => {
        emitProgress({ event: 'heartbeat' });
      }, progressIntervalMs);
    }

    child.stdout.on('data', data => {
      const chunk = data.toString();
      stdout = appendBounded(stdout, chunk, maxOutputBytes);
      stdoutLines.push(chunk);
    });

    child.stderr.on('data', data => {
      const chunk = data.toString();
      stderr = appendBounded(stderr, chunk, maxOutputBytes);
      stderrLines.push(chunk);
    });

    child.stdin.on('error', () => {
      // Herramientas que cierran stdin pronto no deben romper el proceso.
    });

    child.on('error', error => {
      if (settled) return;
      settled = true;
      cleanup();
      error.stdout = stdout;
      error.stderr = stderr;
      error.durationMs = Date.now() - startedAt;
      error.cancelled = cancelled;
      onEnd({ name, status: 'error', error: error.message, durationMs: error.durationMs });
      reject(error);
    });

    child.on('close', code => {
      if (settled) return;
      settled = true;
      closed = true;
      stdoutLines.flush();
      stderrLines.flush();
      cleanup();
      const durationMs = Date.now() - startedAt;
      const result = {
        stdout,
        stderr,
        exitCode: code,
        durationMs,
        timedOut,
        idleTimedOut,
        cancelled,
        lastOutput,
        lastOutputAt
      };
      onEnd({ name, status: cancelled ? 'cancelled' : timedOut || idleTimedOut ? 'timeout' : 'closed', exitCode: code, durationMs });
      resolve(result);
    });

    if (input !== null && input !== undefined) {
      child.stdin.end(input);
    } else {
      child.stdin.end();
    }
  });
}

function errorFromRunResult(command, result) {
  const error = new Error([
    String(result.stderr || '').trim(),
    `${command} finalizo con codigo ${result.exitCode}`
  ].filter(Boolean).join('\n'));
  error.stdout = result.stdout || '';
  error.stderr = result.stderr || '';
  error.exitCode = result.exitCode;
  error.timedOut = result.timedOut;
  error.idleTimedOut = result.idleTimedOut;
  error.cancelled = result.cancelled;
  error.durationMs = result.durationMs;
  return error;
}

module.exports = {
  errorFromRunResult,
  runToolControlled
};
