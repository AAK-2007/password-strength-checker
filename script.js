/* Password Strength Checker
 * Everything runs locally in the browser — the password is never sent anywhere.
 */
(() => {
    'use strict';

    // ---------- Elements ----------
    const $ = (id) => document.getElementById(id);
    const passwordInput = $('password-input');
    const toggleBtn = $('toggle-visibility');
    const generateBtn = $('generate-btn');
    const copyBtn = $('copy-btn');
    const themeToggle = $('theme-toggle');
    const toast = $('toast');
    const strengthBar = $('strength-bar');
    const strengthLabel = $('strength-label');
    const crackTimeLabel = $('crack-time');
    const tipsContent = $('tips-content');

    const requirementEls = {
        length: $('req-length'),
        uppercase: $('req-uppercase'),
        lowercase: $('req-lowercase'),
        number: $('req-number'),
        special: $('req-special'),
    };

    // ---------- Data ----------
    const MIN_LENGTH = 8;
    const GENERATED_LENGTH = 16;
    const GUESSES_PER_SECOND = 1e10; // offline attack on a fast GPU rig

    const CHARSETS = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        number: '0123456789',
        special: '!@#$%^&*()-_=+[]{};:,.<>?/~',
    };

    const PATTERNS = {
        lowercase: /[a-z]/,
        uppercase: /[A-Z]/,
        number: /[0-9]/,
        special: /[^A-Za-z0-9]/, // any symbol, space or non-Latin character
    };

    // Frequently leaked passwords and base words (checked after normalising
    // case, leetspeak and trailing digits/symbols, so "P@ssw0rd123!" is caught).
    const COMMON = new Set([
        '123456', '1234567', '12345678', '123456789', '1234567890', '12345', '1234', '111111', '000000',
        '123123', '654321', '666666', '121212', '112233', '159753', '987654321', '123321', '7777777',
        'password', 'passw0rd', 'pass', 'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbnm', 'qwe',
        'qazwsx', '1q2w3e4r', '1qaz2wsx', 'abc', 'abcd', 'abcdef', 'abc123', 'letmein', 'welcome', 'login',
        'admin', 'administrator', 'root', 'user', 'guest', 'test', 'default', 'changeme', 'secret',
        'iloveyou', 'love', 'lovely', 'princess', 'sunshine', 'flower', 'angel', 'baby', 'babygirl',
        'football', 'baseball', 'soccer', 'cricket', 'hockey', 'basketball', 'monkey', 'dragon', 'tiger',
        'master', 'shadow', 'superman', 'batman', 'spiderman', 'starwars', 'pokemon', 'ninja', 'hacker',
        'charlie', 'michael', 'jordan', 'thomas', 'daniel', 'ashley', 'jessica', 'hunter', 'killer',
        'freedom', 'whatever', 'trustno1', 'jesus', 'god', 'cookie', 'cheese', 'chocolate', 'summer',
        'winter', 'india', 'mumbai', 'computer', 'internet', 'samsung', 'apple', 'google', 'facebook',
        'instagram', 'minecraft', 'fortnite', 'family', 'friends', 'hello', 'helloworld', 'mypassword',
        'secure', 'security', 'access', 'matrix', 'silver', 'golden', 'diamond', 'pepper', 'ginger',
        'buster', 'harley', 'ranger', 'mustang', 'ferrari', 'liverpool', 'chelsea', 'arsenal', 'barcelona',
    ]);

    const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];
    const LEET = { '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't' };

    const LEVELS = [
        { key: 'weak', label: 'Weak', width: 20 },
        { key: 'fair', label: 'Fair', width: 40 },
        { key: 'good', label: 'Good', width: 60 },
        { key: 'strong', label: 'Strong', width: 80 },
        { key: 'very-strong', label: 'Very Strong', width: 100 },
    ];

    const DEFAULT_TIPS = [
        'Use a mix of uppercase, lowercase, numbers, and symbols',
        'Avoid common words and personal information',
        'Make it at least 12 characters long for better security',
        'Consider using a password manager',
        'Never reuse passwords across different accounts',
    ];

    // ---------- Secure randomness ----------
    function randomInt(max) {
        // Uniform integer in [0, max) using rejection sampling (no modulo bias).
        const limit = Math.floor(0x100000000 / max) * max;
        const buf = new Uint32Array(1);
        do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
        return buf[0] % max;
    }

    function generatePassword(length = GENERATED_LENGTH) {
        const sets = Object.values(CHARSETS);
        const all = sets.join('');
        // One character from each set, so every requirement is met…
        const chars = sets.map((set) => set[randomInt(set.length)]);
        // …then fill the rest from the full pool.
        while (chars.length < length) chars.push(all[randomInt(all.length)]);
        // Fisher–Yates shuffle so the guaranteed characters aren't in fixed spots.
        for (let i = chars.length - 1; i > 0; i--) {
            const j = randomInt(i + 1);
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        return chars.join('');
    }

    // ---------- Analysis ----------
    function normalise(word) {
        return word.toLowerCase().replace(/[@4310!$57+]/g, (c) => LEET[c]);
    }

    function isCommonPassword(password) {
        const lower = password.toLowerCase();
        if (COMMON.has(lower)) return true;
        // Strip trailing digits/symbols ("summer2024!") and leading digits ("123password").
        const core = lower.replace(/[\d\W_]+$/, '').replace(/^\d+/, '');
        if (core && COMMON.has(core)) return true;
        // Leetspeak: "P@ssw0rd123!" → "p@ssw0rd" → "password"
        const leet = normalise(lower.replace(/[\d\W_]{1,6}$/, ''));
        return Boolean(leet) && (COMMON.has(leet) || COMMON.has(normalise(lower)));
    }

    function countSequences(lower) {
        // Counts characters that sit in runs of 3+ consecutive or keyboard-adjacent characters.
        let inRun = 0;
        let run = 1;
        const step = (a, b) => {
            if (b.charCodeAt(0) - a.charCodeAt(0) === 1 || a.charCodeAt(0) - b.charCodeAt(0) === 1) return true;
            return KEYBOARD_ROWS.some((row) => {
                const i = row.indexOf(a);
                return i !== -1 && (row[i + 1] === b || row[i - 1] === b);
            });
        };
        for (let i = 1; i <= lower.length; i++) {
            if (i < lower.length && step(lower[i - 1], lower[i])) {
                run++;
            } else {
                if (run >= 3) inRun += run;
                run = 1;
            }
        }
        return inRun;
    }

    function analyzePassword(password) {
        const chars = Array.from(password); // counts emoji / non-Latin characters correctly
        const length = chars.length;

        const checks = {
            length: length >= MIN_LENGTH,
            lowercase: PATTERNS.lowercase.test(password),
            uppercase: PATTERNS.uppercase.test(password),
            number: PATTERNS.number.test(password),
            special: PATTERNS.special.test(password),
        };

        const isCommon = length > 0 && isCommonPassword(password);
        const lower = password.toLowerCase();

        // Character pool size → raw entropy
        let pool = 0;
        if (checks.lowercase) pool += 26;
        if (checks.uppercase) pool += 26;
        if (checks.number) pool += 10;
        if (checks.special) pool += 33;
        if (/[^\x00-\x7F]/.test(password)) pool += 100;

        // Characters that add little real strength count for less.
        const repeats = (password.match(/(.)\1{2,}/g) || []).reduce((n, m) => n + m.length - 1, 0);
        const sequences = countSequences(lower);
        const years = (password.match(/(19|20)\d{2}/g) || []).length * 3;
        const uniqueRatio = length ? new Set(chars).size / length : 1;

        let effectiveLength = length - repeats - sequences * 0.75 - years;
        if (uniqueRatio < 0.5) effectiveLength *= uniqueRatio + 0.3;
        effectiveLength = Math.max(effectiveLength, length ? 1 : 0);

        let entropy = pool ? effectiveLength * Math.log2(pool) : 0;
        if (isCommon) entropy = Math.min(entropy, 10);

        return {
            ...checks,
            charCount: length,
            isCommon,
            hasSequence: sequences > 0,
            hasRepeats: repeats > 0,
            hasYear: years > 0,
            entropy,
            level: levelFor(entropy, length, checks),
        };
    }

    function levelFor(entropy, length, checks) {
        let level;
        if (entropy < 28) level = 0;
        else if (entropy < 45) level = 1;
        else if (entropy < 70) level = 2;
        else if (entropy < 90) level = 3;
        else level = 4;

        // Short passwords can't be better than "Fair", whatever their mix.
        if (length < MIN_LENGTH) level = Math.min(level, 1);
        // "Very Strong" needs 12+ characters and at least 3 character types.
        const variety = ['lowercase', 'uppercase', 'number', 'special'].filter((k) => checks[k]).length;
        if (level === 4 && (length < 12 || variety < 3)) level = 3;
        return level;
    }

    function formatCrackTime(entropy) {
        // On average an attacker finds the password after searching half the space.
        const seconds = Math.pow(2, entropy - 1) / GUESSES_PER_SECOND;
        if (seconds < 1) return 'Instant';
        const units = [
            ['second', 60], ['minute', 60], ['hour', 24], ['day', 30], ['month', 12], ['year', 100],
        ];
        let value = seconds;
        for (const [name, size] of units) {
            if (value < size) {
                const n = Math.round(value);
                return `${n} ${name}${n === 1 ? '' : 's'}`;
            }
            value /= size;
        }
        // value is now in centuries
        if (value < 10) return `${Math.round(value)} centur${Math.round(value) === 1 ? 'y' : 'ies'}`;
        if (value < 10000) return 'Thousands of years';
        if (value < 1e7) return 'Millions of years';
        return 'Billions of years+';
    }

    // ---------- Rendering ----------
    function render() {
        const password = passwordInput.value;
        const analysis = analyzePassword(password);

        for (const [key, el] of Object.entries(requirementEls)) {
            const met = password.length > 0 && analysis[key];
            el.classList.toggle('met', met);
            el.setAttribute('aria-label', `${el.textContent.trim()}: ${met ? 'met' : 'not met'}`);
        }

        strengthBar.className = 'strength-bar';
        strengthLabel.className = 'strength-label';

        if (!password) {
            strengthBar.style.width = '0%';
            strengthLabel.textContent = 'Enter a password';
            crackTimeLabel.textContent = '';
            renderTips(DEFAULT_TIPS);
            return;
        }

        const level = analysis.isCommon ? LEVELS[0] : LEVELS[analysis.level];
        strengthBar.classList.add(level.key);
        strengthBar.style.width = `${analysis.isCommon ? 10 : level.width}%`;
        strengthLabel.classList.add(level.key);
        strengthLabel.textContent = analysis.isCommon ? 'Too Common' : level.label;

        crackTimeLabel.textContent = 'Time to crack: ';
        const strong = document.createElement('strong');
        strong.textContent = analysis.isCommon ? 'Instant' : formatCrackTime(analysis.entropy);
        crackTimeLabel.appendChild(strong);

        renderTips(buildTips(analysis));
    }

    function buildTips(a) {
        if (a.isCommon) {
            return ['This is (or is based on) a very common password. Attackers try these first — choose something unique.'];
        }
        const tips = [];
        if (!a.length) tips.push(`Make it at least ${MIN_LENGTH} characters long (12+ recommended)`);
        else if (a.charCount < 12) tips.push('Make it 12+ characters — length matters more than anything else');
        if (!a.uppercase) tips.push('Add an uppercase letter');
        if (!a.lowercase) tips.push('Add a lowercase letter');
        if (!a.number) tips.push('Include a number');
        if (!a.special) tips.push('Add a symbol like ! @ # $ or a space');
        if (a.hasSequence) tips.push('Avoid sequences like "abc", "123" or "qwerty"');
        if (a.hasRepeats) tips.push('Avoid repeating the same character ("aaa")');
        if (a.hasYear) tips.push('Avoid years and dates — they are easy to guess');
        if (!tips.length) tips.push(a.level >= 4 ? 'Excellent password! Store it in a password manager.' : 'Good job! A few more characters would make it even stronger.');
        return tips;
    }

    function renderTips(tips) {
        const ul = document.createElement('ul');
        ul.className = 'tips-list';
        for (const tip of tips) {
            const li = document.createElement('li');
            li.textContent = tip;
            ul.appendChild(li);
        }
        tipsContent.replaceChildren(ul);
    }

    // ---------- UI actions ----------
    let toastTimer;
    function showToast(message) {
        toast.textContent = message;
        toast.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => toast.classList.remove('show'), 2500);
    }

    function setVisibility(visible) {
        passwordInput.type = visible ? 'text' : 'password';
        toggleBtn.setAttribute('aria-pressed', String(visible));
        toggleBtn.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
        toggleBtn.title = visible ? 'Hide password' : 'Show password';
    }

    async function copyPassword() {
        const value = passwordInput.value;
        if (!value) {
            showToast('Nothing to copy yet');
            return;
        }
        try {
            await navigator.clipboard.writeText(value);
            showToast('Password copied to clipboard!');
        } catch {
            // Fallback for browsers/contexts without the async Clipboard API
            const wasPassword = passwordInput.type === 'password';
            if (wasPassword) passwordInput.type = 'text';
            passwordInput.select();
            const ok = document.execCommand && document.execCommand('copy');
            if (wasPassword) passwordInput.type = 'password';
            passwordInput.setSelectionRange(value.length, value.length);
            showToast(ok ? 'Password copied to clipboard!' : 'Copy failed — select and copy manually');
        }
    }

    // ---------- Theme ----------
    const root = document.documentElement;
    function applyTheme(theme) {
        root.setAttribute('data-theme', theme);
        themeToggle.setAttribute('aria-label', theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
        themeToggle.title = themeToggle.getAttribute('aria-label');
    }

    themeToggle.addEventListener('click', () => {
        const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        applyTheme(next);
        try { localStorage.setItem('theme', next); } catch { /* storage unavailable */ }
    });

    // ---------- Wire up ----------
    passwordInput.addEventListener('input', render);
    toggleBtn.addEventListener('click', () => setVisibility(passwordInput.type === 'password'));
    copyBtn.addEventListener('click', copyPassword);
    generateBtn.addEventListener('click', () => {
        passwordInput.value = generatePassword();
        setVisibility(true);
        render();
        passwordInput.focus();
    });

    applyTheme(root.getAttribute('data-theme') || 'dark');
    setVisibility(false);
    render();
})();
