'use strict';

/* ==========================================================================
   1. CRYPTOGRAPHIC RANDOMNESS HELPERS
   Everything below is built on window.crypto.getRandomValues().
   Math.random() is never used anywhere in this file.
   ========================================================================== */

/**
 * Returns a cryptographically secure random integer in [0, max).
 * Uses rejection sampling over a Uint32Array to eliminate modulo bias.
 */
function getSecureRandomInt(max) {
  if (max <= 0) return 0;
  const range = Math.floor(max);
  // Largest multiple of `range` that fits in 32 bits, used to reject
  // any draw that would otherwise skew the distribution.
  const maxUint32 = 0xFFFFFFFF;
  const limit = maxUint32 - (maxUint32 % range);

  const buf = new Uint32Array(1);
  let value;
  do {
    window.crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);

  return value % range;
}

/** Picks one random element from an array using the secure RNG. */
function secureChoice(arr) {
  return arr[getSecureRandomInt(arr.length)];
}

/** In-place, cryptographically secure Fisher-Yates shuffle. */
function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/* ==========================================================================
   2. CHARACTER POOLS
   ========================================================================== */

const POOLS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?/~`',
};

const SIMILAR_CHARS = 'il1LoO0';

function stripSimilar(str) {
  return str.split('').filter((c) => !SIMILAR_CHARS.includes(c)).join('');
}

/* ==========================================================================
   3. WORDLIST (short, clear, memorable — EFF-style)
   ========================================================================== */

const WORDLIST = [
  'anchor','arctic','autumn','banjo','basalt','basket','beacon','birch','bishop',
  'blanket','blossom','bramble','breeze','bridge','bronze','bucket','bugle','cabin',
  'candle','canyon','carbon','cedar','chalk','chant','charm','cherry','chisel',
  'cinder','clover','cobalt','comet','copper','coral','cosmic','cotton','crater',
  'cradle','crimson','crystal','current','cypress','dagger','dawn','delta','desert',
  'diamond','dolphin','dragon','drift','dune','eagle','ember','engine','falcon',
  'feather','fern','fiddle','flame','flannel','flint','forest','forge','fossil',
  'fountain','fox','frost','galaxy','garden','gecko','glacier','glimmer','goblin',
  'granite','gravel','grove','gully','hamlet','harbor','harvest','hazel','heron',
  'hollow','honey','hornet','hunter','iguana','indigo','island','ivory','jasper',
  'jungle','kayak','kettle','kingdom','kite','lagoon','lantern','laurel','ledge',
  'lemon','lichen','linen','lotus','lumber','lynx','magnet','mango','maple',
  'marble','marsh','meadow','mellow','mesa','meteor','mint','mirage','mist',
  'monarch','moss','mountain','mural','nectar','nettle','nomad','oak','oasis',
  'obelisk','onyx','opal','orbit','orchard','osprey','otter','panther','papyrus',
  'parcel','pebble','pepper','petal','phoenix','pigeon','pilot','pine','plateau',
  'plum','pocket','poplar','prairie','prism','quartz','quiver','rabbit','raccoon',
  'rapid','raven','reef','ridge','ripple','river','rocket','rooster','saddle',
  'saffron','sage','salmon','sandal','sapling','satin','savanna','scarlet','sequoia',
  'shadow','shale','shelter','shrike','signal','silver','sketch','slate','sliver',
  'sonnet','sparrow','spiral','spruce','stallion','starling','statue','summit','sundial',
  'sunset','swallow','tangerine','tavern','tempo','terrace','thicket','thistle','thunder',
  'timber','topaz','torch','trellis','tulip','tundra','tunnel','turtle','umbrella',
  'valley','velvet','vessel','violet','vortex','walnut','warbler','willow','window',
  'winter','wolf','wren','yonder','zephyr','zigzag',
];

/* ==========================================================================
   4. GENERATION LOGIC
   ========================================================================== */

function generateRandomPassword({ length, useUpper, useLower, useNumbers, useSymbols, excludeSimilar }) {
  const categories = [];
  if (useUpper) categories.push(excludeSimilar ? stripSimilar(POOLS.upper) : POOLS.upper);
  if (useLower) categories.push(excludeSimilar ? stripSimilar(POOLS.lower) : POOLS.lower);
  if (useNumbers) categories.push(excludeSimilar ? stripSimilar(POOLS.numbers) : POOLS.numbers);
  if (useSymbols) categories.push(POOLS.symbols);

  if (categories.length === 0) return '';

  const fullPool = categories.join('');
  const result = [];

  // Guarantee at least one character from every selected category.
  for (const cat of categories) {
    result.push(secureChoice(cat.split('')));
  }

  // Fill the remaining length from the combined pool.
  while (result.length < length) {
    result.push(secureChoice(fullPool.split('')));
  }

  secureShuffle(result);
  const password = result.join('');

  // Memory hygiene: the intermediate character array is no longer needed
  // once joined — overwrite its slots before dropping the reference so a
  // stale copy of the plaintext doesn't linger in this array past its use.
  result.fill('\0');

  return password;
}

function generatePassphrase({ wordCount, separator, capitalize, appendNumber }) {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let word = secureChoice(WORDLIST);
    if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
    words.push(word);
  }
  let phrase = words.join(separator);
  if (appendNumber) {
    phrase += separator + String(getSecureRandomInt(100)).padStart(2, '0');
  }
  words.fill('\0');
  return phrase;
}

function generatePin(length) {
  let pin = '';
  for (let i = 0; i < length; i++) {
    pin += String(getSecureRandomInt(10));
  }
  return pin;
}

/* ==========================================================================
   5. PASSWORD ANALYZER
   ========================================================================== */

function detectPoolSize(password) {
  let n = 0;
  if (/[a-z]/.test(password)) n += 26;
  if (/[A-Z]/.test(password)) n += 26;
  if (/[0-9]/.test(password)) n += 10;
  if (/[^a-zA-Z0-9]/.test(password)) n += 32;
  return n;
}

function calculateEntropy(password) {
  if (!password) return 0;
  const n = detectPoolSize(password);
  if (n === 0) return 0;
  return password.length * Math.log2(n);
}

/**
 * Converts a number of seconds into a human-friendly duration string.
 */
function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds < 0) return 'Instant';
  if (seconds < 1) return 'Instant';

  const units = [
    { label: 'second', secs: 1 },
    { label: 'minute', secs: 60 },
    { label: 'hour', secs: 3600 },
    { label: 'day', secs: 86400 },
    { label: 'year', secs: 31557600 },
    { label: 'century', secs: 31557600 * 100 },
  ];

  // Extremely large numbers: express in centuries with scientific-style rounding.
  const centuries = seconds / units[5].secs;
  if (centuries >= 1e6) {
    if (centuries >= 1e12) return `${(centuries / 1e12).toFixed(1)} trillion centuries`;
    if (centuries >= 1e9) return `${(centuries / 1e9).toFixed(1)} billion centuries`;
    return `${(centuries / 1e6).toFixed(1)} million centuries`;
  }
  if (centuries >= 1) return `${Math.round(centuries).toLocaleString()} centuries`;

  for (let i = units.length - 2; i >= 0; i--) {
    const value = seconds / units[i].secs;
    if (value >= 1) {
      const rounded = value >= 10 ? Math.round(value) : Math.round(value * 10) / 10;
      return `${rounded} ${units[i].label}${rounded === 1 ? '' : 's'}`;
    }
  }
  return 'Instant';
}

function estimateCrackTime(entropyBits, guessesPerSecond) {
  // Average case: an attacker finds the answer after searching half the space.
  const totalCombinations = Math.pow(2, entropyBits);
  const seconds = totalCombinations / (2 * guessesPerSecond);
  return formatDuration(seconds);
}

function classifyStrength(entropyBits) {
  if (entropyBits <= 0) return { level: 0, label: 'Enter a password' };
  if (entropyBits < 28) return { level: 1, label: 'Very weak' };
  if (entropyBits < 40) return { level: 2, label: 'Weak' };
  if (entropyBits < 60) return { level: 3, label: 'Medium' };
  if (entropyBits < 80) return { level: 4, label: 'Strong' };
  return { level: 5, label: 'Very strong' };
}

const STRENGTH_COLORS = ['', '#f0475c', '#f5a524', '#eee15a', '#34d399', '#22e0a0'];

/**
 * Runs the bundled zxcvbn pattern-matching engine (dictionary words,
 * keyboard walks like "qwerty", repeats, common substitutions such as
 * "P@ssw0rd") so a password isn't judged on raw character-pool math
 * alone. Returns null if the library failed to load for any reason —
 * the analyzer still works from character-set entropy in that case.
 */
function runPatternAnalysis(password) {
  if (typeof window.zxcvbn !== 'function' || !password) return null;
  try {
    return window.zxcvbn(password);
  } catch (err) {
    return null;
  }
}

function runAnalyzer(password) {
  const entropy = calculateEntropy(password);
  let { level, label } = classifyStrength(password ? entropy : 0);

  // Pattern-aware second opinion: if zxcvbn recognizes the password as a
  // predictable pattern, it will report a low score (0-4) even when the
  // raw character-pool entropy looks high. We take whichever verdict is
  // more conservative, so "P@ssw0rd123!" can't hide behind its charset math.
  const patternResult = runPatternAnalysis(password);
  if (patternResult) {
    const patternLevel = patternResult.score + 1; // 0-4 -> 1-5
    if (patternLevel < level) {
      level = patternLevel;
      label = classifyStrength(0).label; // placeholder, overwritten below
      const labelsByLevel = ['Enter a password', 'Very weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
      label = labelsByLevel[level];
    }
  }

  document.getElementById('stat-entropy').innerHTML =
    `${entropy.toFixed(1)} <small>bits</small>`;
  document.getElementById('stat-crack-fast').textContent =
    password ? estimateCrackTime(entropy, 1e10) : '—';
  document.getElementById('stat-crack-cluster').textContent =
    password ? estimateCrackTime(entropy, 1e11) : '—';

  const zxcvbnStatEl = document.getElementById('stat-zxcvbn');
  if (patternResult) {
    zxcvbnStatEl.textContent = patternResult.crack_times_display.offline_fast_hashing_1e10_per_second;
  } else {
    zxcvbnStatEl.textContent = password ? 'Unavailable' : '—';
  }

  const feedbackEl = document.getElementById('pattern-feedback');
  if (patternResult && (patternResult.feedback.warning || patternResult.feedback.suggestions.length)) {
    const parts = [patternResult.feedback.warning, ...patternResult.feedback.suggestions].filter(Boolean);
    feedbackEl.textContent = parts.join(' ');
    feedbackEl.classList.add('is-visible');
  } else {
    feedbackEl.textContent = '';
    feedbackEl.classList.remove('is-visible');
  }

  const bar = document.getElementById('strength-bar');
  const segments = bar.querySelectorAll('span');
  segments.forEach((seg, i) => {
    if (i < level) {
      seg.style.background = STRENGTH_COLORS[level];
      seg.style.boxShadow = `0 0 8px ${STRENGTH_COLORS[level]}66`;
    } else {
      seg.style.background = '';
      seg.style.boxShadow = '';
    }
  });

  const labelEl = document.getElementById('strength-label');
  labelEl.textContent = label;
  labelEl.style.color = level ? STRENGTH_COLORS[level] : '';

  const rules = {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^a-zA-Z0-9]/.test(password),
  };
  for (const [rule, met] of Object.entries(rules)) {
    const li = document.querySelector(`.rule-checklist li[data-rule="${rule}"]`);
    li.classList.toggle('is-met', met);
  }
}

/* ==========================================================================
   6. UI WIRING
   ========================================================================== */

let currentMode = 'random';
let currentPinLength = 6;
let clipboardClearTimer = null;

const outputField = document.getElementById('output-field');
const analyzerInput = document.getElementById('analyzer-input');

function readRandomOptions() {
  return {
    length: Number(document.getElementById('rand-length').value),
    useUpper: document.getElementById('opt-upper').checked,
    useLower: document.getElementById('opt-lower').checked,
    useNumbers: document.getElementById('opt-numbers').checked,
    useSymbols: document.getElementById('opt-symbols').checked,
    excludeSimilar: document.getElementById('opt-exclude-similar').checked,
  };
}

function readPassphraseOptions() {
  return {
    wordCount: Number(document.getElementById('phrase-words').value),
    separator: document.getElementById('phrase-separator').value,
    capitalize: document.getElementById('opt-capitalize').checked,
    appendNumber: document.getElementById('opt-append-number').checked,
  };
}

function generateForCurrentMode() {
  let result = '';
  if (currentMode === 'random') {
    const opts = readRandomOptions();
    if (!opts.useUpper && !opts.useLower && !opts.useNumbers && !opts.useSymbols) {
      result = '';
      outputField.placeholder = 'Select at least one character set';
    } else {
      result = generateRandomPassword(opts);
    }
  } else if (currentMode === 'passphrase') {
    result = generatePassphrase(readPassphraseOptions());
  } else if (currentMode === 'pin') {
    result = generatePin(currentPinLength);
  }

  outputField.value = result;
  runAnalyzer(result);
  return result;
}

/* ---- Mode tab switching ---- */
document.querySelectorAll('.mode-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.mode-tab').forEach((t) => {
      t.classList.remove('is-active');
      t.setAttribute('aria-selected', 'false');
    });
    tab.classList.add('is-active');
    tab.setAttribute('aria-selected', 'true');

    currentMode = tab.dataset.mode;
    document.querySelectorAll('.mode-body').forEach((body) => {
      body.classList.toggle('is-active', body.dataset.modeBody === currentMode);
    });
    generateForCurrentMode();
  });
});

/* ---- PIN length segmented control ---- */
document.querySelectorAll('.segment').forEach((seg) => {
  seg.addEventListener('click', () => {
    document.querySelectorAll('.segment').forEach((s) => s.classList.remove('is-active'));
    seg.classList.add('is-active');
    currentPinLength = Number(seg.dataset.pinLength);
    generateForCurrentMode();
  });
});

/* ---- Live-updating sliders ---- */
const randLength = document.getElementById('rand-length');
randLength.addEventListener('input', () => {
  document.getElementById('rand-length-value').textContent = randLength.value;
  generateForCurrentMode();
});

const phraseWords = document.getElementById('phrase-words');
phraseWords.addEventListener('input', () => {
  document.getElementById('phrase-words-value').textContent = phraseWords.value;
  generateForCurrentMode();
});

/* ---- All other controls regenerate on change ---- */
[
  'opt-upper', 'opt-lower', 'opt-numbers', 'opt-symbols', 'opt-exclude-similar',
  'phrase-separator', 'opt-capitalize', 'opt-append-number',
].forEach((id) => {
  document.getElementById(id).addEventListener('change', generateForCurrentMode);
});

/* ---- Regenerate button ---- */
document.getElementById('btn-regen').addEventListener('click', generateForCurrentMode);

/**
 * Copies text to the clipboard, then overwrites the clipboard with an
 * empty string 30 seconds later — the OS clipboard is plaintext and
 * readable by any other app, browser extension, or clipboard-history
 * tool while it sits there, so this limits that exposure window.
 * Note: this is a best-effort mitigation, not a guarantee — if the user
 * copies something else in the meantime, this will overwrite that too,
 * and some browsers require the tab to still be focused for the
 * follow-up write to succeed.
 */
async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(async () => {
    try {
      await navigator.clipboard.writeText('');
    } catch (err) {
      // Clipboard access may be blocked if the tab lost focus/permission;
      // nothing more we can do from client-side JS at that point.
    }
  }, 30000);
}

/* ---- Copy to clipboard ---- */
document.getElementById('btn-copy').addEventListener('click', async () => {
  const value = outputField.value;
  if (!value) return;

  try {
    await copyToClipboard(value);
  } catch (err) {
    // Fallback for environments without Clipboard API permission.
    const wasMasked = outputField.type === 'password';
    outputField.type = 'text';
    outputField.select();
    document.execCommand('copy');
    if (wasMasked) outputField.type = 'password';
  }

  const btn = document.getElementById('btn-copy');
  const feedback = document.getElementById('copy-feedback');
  btn.classList.add('is-copied');
  feedback.textContent = 'Copied! Clipboard will auto-clear in 30 seconds.';
  feedback.classList.add('is-visible');

  setTimeout(() => {
    btn.classList.remove('is-copied');
    feedback.classList.remove('is-visible');
  }, 2200);
});

/* ---- Reveal/hide toggles (password fields stay masked by default) ---- */
function wireRevealToggle(buttonId, fieldId, openIconId, closedIconId) {
  const btn = document.getElementById(buttonId);
  const field = document.getElementById(fieldId);
  const openIcon = document.getElementById(openIconId);
  const closedIcon = document.getElementById(closedIconId);

  btn.addEventListener('click', () => {
    const isMasked = field.type === 'password';
    field.type = isMasked ? 'text' : 'password';
    btn.setAttribute('aria-pressed', String(isMasked));
    btn.title = isMasked ? 'Hide password' : 'Show password';
    openIcon.style.display = isMasked ? 'none' : '';
    closedIcon.style.display = isMasked ? '' : 'none';
  });
}

wireRevealToggle('btn-reveal', 'output-field', 'icon-eye-open', 'icon-eye-closed');
wireRevealToggle('btn-reveal-analyzer', 'analyzer-input', 'icon-eye-open-2', 'icon-eye-closed-2');

/* ---- Analyzer field: independent live analysis ---- */
analyzerInput.addEventListener('input', () => {
  runAnalyzer(analyzerInput.value);
});

/* ==========================================================================
   7. INITIALIZATION
   ========================================================================== */
document.addEventListener('DOMContentLoaded', () => {
  generateForCurrentMode();
});