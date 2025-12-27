document.addEventListener('DOMContentLoaded', () => {
    const themeToggleBtn = document.getElementById('themeToggle');
    const body = document.body;
    
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        body.classList.add('theme-light');
        themeToggleBtn.checked = true;
    }

    themeToggleBtn.addEventListener('change', () => {
        if (themeToggleBtn.checked) {
            body.classList.add('theme-light');
            localStorage.setItem('theme', 'light');
        } else {
            body.classList.remove('theme-light');
            localStorage.setItem('theme', 'dark');
        }
    });


    const domainInput = document.getElementById('domainInput');
    const scanBtn = document.getElementById('scanBtn');
    const errorMsg = document.getElementById('errorMsg');
    const progressBar = document.getElementById('progressBar');
    const statusText = document.getElementById('statusText');
    const progressSection = document.getElementById('progressSection');
    const resultsBody = document.getElementById('resultsBody');
    const statsBlock = document.getElementById('statsBlock');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const showMoreContainer = document.getElementById('showMoreContainer');
    const showMoreBtn = document.getElementById('showMoreBtn');
    const hiddenCountSpan = document.getElementById('hiddenCount');
    
    const copyBtn = document.getElementById('copyBtn');
    const exportTxtBtn = document.getElementById('exportTxtBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    const clearBtn = document.getElementById('clearBtn');

    let abortController = null;
    let results = [];
    let startTime = 0;
    let foundCount = 0;
    const MAX_VISIBLE_RESULTS = 10;
    let showAllResults = false;
    const CONCURRENCY_LIMIT = 10;
    let uniqueSubdomains = new Set();
    let candidateQueue = [];
    let totalCandidates = 0;
    let completedCandidates = 0;
    let sourcesCompleted = false;

    const cfRanges = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
    ];

    scanBtn.addEventListener('click', startScan);
    clearBtn.addEventListener('click', clearResults);
    copyBtn.addEventListener('click', copyAllToClipboard);
    exportTxtBtn.addEventListener('click', exportToTxt);
    exportJsonBtn.addEventListener('click', exportToJson);
    showMoreBtn.addEventListener('click', () => {
        showAllResults = true;
        renderResults();
    });
    
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => sortResults(th.dataset.sort));
    });

    resultsBody.addEventListener('click', (e) => {
        if (e.target.classList.contains('ip-copy')) {
            const ip = e.target.textContent;
            navigator.clipboard.writeText(ip).then(() => {
                const original = e.target.textContent;
                e.target.textContent = 'Copied!';
                setTimeout(() => e.target.textContent = original, 1500);
            });
        }
    });

    function enqueueCandidates(subdomains) {
        subdomains.forEach(sub => {
            if (!uniqueSubdomains.has(sub)) {
                uniqueSubdomains.add(sub);
                candidateQueue.push(sub);
            }
        });
        totalCandidates = uniqueSubdomains.size;
        if (totalCandidates > 0) {
            updateProgress(40, `Verifying ${totalCandidates} candidates...`);
        }
        updateStats();
    }

    async function startVerification(signal) {
        const workers = [];
        for (let i = 0; i < CONCURRENCY_LIMIT; i++) {
            workers.push((async () => {
                while (!signal.aborted) {
                    const subdomain = candidateQueue.shift();
                    if (!subdomain) {
                        if (sourcesCompleted) {
                            break;
                        }
                        await new Promise(resolve => setTimeout(resolve, 50));
                        continue;
                    }
                    try {
                        const ip = await resolveIp(subdomain, signal);
                        if (ip) {
                            const time = await checkTime(subdomain, signal);
                            const isCF = isCloudflareIp(ip);
                            addResult({
                                subdomain,
                                ip,
                                isCF,
                                time
                            });
                        }
                    } catch (e) {
                    } finally {
                        completedCandidates++;
                        if (totalCandidates > 0) {
                            const percent = 40 + Math.floor((completedCandidates / totalCandidates) * 60);
                            updateProgress(percent, `Verifying... ${completedCandidates}/${totalCandidates}`);
                        }
                    }
                }
            })());
        }
        await Promise.all(workers);
    }

    async function startScan() {
        const domain = domainInput.value.trim().toLowerCase();
        if (!validateDomain(domain)) {
            showError('Invalid domain format. Use format like "example.com"');
            return;
        }
        
        showError('');
        clearResults(false);
        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        progressSection.classList.add('active');
        updateProgress(5, 'Initializing...');
        
        abortController = new AbortController();
        const signal = abortController.signal;
        startTime = performance.now();
        uniqueSubdomains = new Set();
        candidateQueue = [];
        totalCandidates = 0;
        completedCandidates = 0;
        sourcesCompleted = false;

        try {
            updateProgress(20, 'Querying public APIs...');
            loadingSpinner.classList.remove('hidden');
            
            const crtPromise = fetchCrtSh(domain, signal)
                .then(subs => {
                    enqueueCandidates(subs);
                })
                .catch(() => {});

            const hackerTargetPromise = fetchHackerTarget(domain, signal)
                .then(subs => {
                    enqueueCandidates(subs);
                })
                .catch(() => {});

            const verificationPromise = startVerification(signal);

            await Promise.all([crtPromise, hackerTargetPromise]);
            sourcesCompleted = true;
            loadingSpinner.classList.add('hidden');

            await verificationPromise;

            if (!signal.aborted) {
                updateProgress(100, 'Done');
            }

        } catch (err) {
            if (err.name === 'AbortError') {
                updateProgress(100, 'Aborted');
            } else {
                showError('An error occurred: ' + err.message);
            }
        } finally {
            loadingSpinner.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.textContent = 'Scan';
            abortController = null;
        }
    }

    function validateDomain(domain) {
        const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        return regex.test(domain);
    }

    function showError(msg) {
        errorMsg.textContent = msg;
    }

    function updateProgress(percent, text) {
        progressBar.style.width = `${percent}%`;
        statusText.textContent = text;
    }

    function updateStats() {
        const elapsed = startTime ? ((performance.now() - startTime) / 1000).toFixed(1) : '0.0';
        const discovered = uniqueSubdomains ? uniqueSubdomains.size : 0;
        statsBlock.textContent = `Discovered: ${discovered} | Resolved: ${foundCount} | Time: ${elapsed}s`;
    }

    async function fetchCrtSh(domain, signal) {
        const url = `https://crt.sh/?q=%.${domain}&output=json`;
        const res = await fetch(url, { signal });
        if (!res.ok) throw new Error('crt.sh failed');
        const data = await res.json();
        const subs = new Set();
        data.forEach(entry => {
            const names = entry.name_value.split('\n');
            names.forEach(name => {
                let clean = name.trim().toLowerCase();
                if (clean.endsWith('.')) {
                    clean = clean.slice(0, -1);
                }
                if (clean.endsWith(domain) && !clean.includes('*')) {
                    subs.add(clean);
                }
            });
        });
        return Array.from(subs);
    }

    async function fetchHackerTarget(domain, signal) {
        const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
        const res = await fetch(url, { signal });
        if (!res.ok) throw new Error('HackerTarget failed');
        const text = await res.text();
        const subs = new Set();
        const lines = text.split('\n');
        lines.forEach(line => {
            const parts = line.split(',');
            if (parts.length >= 1) {
                const sub = parts[0].trim().toLowerCase();
                if (sub.endsWith(domain)) {
                    subs.add(sub);
                }
            }
        });
        return Array.from(subs);
    }

    async function resolveIp(domain, signal) {
        try {
            const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
                headers: { 'Accept': 'application/dns-json' },
                signal
            });
            const data = await res.json();
            if (data.Status === 0 && data.Answer) {
                const aRecord = data.Answer.find(r => r.type === 1);
                if (aRecord) return aRecord.data;
            }
        } catch (e) {
            return null;
        }
        return null;
    }

    function isCloudflareIp(ip) {
        if (!ip) return false;
        
        const ipParts = ip.split('.').map(Number);
        if (ipParts.length !== 4) return false;
        const ipNum = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;

        for (const range of cfRanges) {
            const [rangeIp, prefix] = range.split('/');
            const rangeParts = rangeIp.split('.').map(Number);
            const rangeNum = ((rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3]) >>> 0;
            const mask = (~((1 << (32 - Number(prefix))) - 1)) >>> 0;

            if ((ipNum & mask) === (rangeNum & mask)) {
                return true;
            }
        }
        return false;
    }

    async function checkTime(subdomain, signal) {
        const start = performance.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            
            signal.addEventListener('abort', () => controller.abort());

            await fetch(`https://${subdomain}`, { 
                method: 'HEAD', 
                mode: 'no-cors', 
                signal: controller.signal 
            });
            
            clearTimeout(timeoutId);
            const end = performance.now();
            
            return Math.floor(end - start);
            
        } catch (e) {
            return null;
        }
    }

    function addResult(item) {
        results.push(item);
        foundCount++;
        updateStats();
        renderResults();
    }

    
    function clearResults(clearInput = true) {
        results = [];
        foundCount = 0;
        showAllResults = false;
        resultsBody.innerHTML = '';
        uniqueSubdomains = new Set();
        totalCandidates = 0;
        completedCandidates = 0;
        sourcesCompleted = false;
        loadingSpinner.classList.add('hidden');
        statsBlock.textContent = 'Discovered: 0 | Resolved: 0 | Time: 0s';
        showMoreContainer.classList.add('hidden');
        hiddenCountSpan.textContent = '0';
        if (clearInput) domainInput.value = '';
        progressSection.classList.remove('active');
        if (abortController) abortController.abort();
    }

    function sortResults(key) {
        results.sort((a, b) => {
            let valA = a[key];
            let valB = b[key];
            
            if (valA === null) valA = '';
            if (valB === null) valB = '';

            if (key === 'time') {
                return (a.time || 999999) - (b.time || 999999);
            }

            if (typeof valA === 'boolean') {
                 return (valA === valB) ? 0 : valA ? -1 : 1;
            }
            
            if (valA < valB) return -1;
            if (valA > valB) return 1;
            return 0;
        });

        renderResults();
    }

    function renderResults() {
        resultsBody.innerHTML = '';
        const total = results.length;
        const visibleCount = showAllResults ? total : Math.min(total, MAX_VISIBLE_RESULTS);

        for (let i = 0; i < visibleCount; i++) {
            const item = results[i];
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><a href="http://${item.subdomain}" target="_blank" class="domain-link">${item.subdomain}</a></td>
                <td><span class="ip-copy" title="Click to copy">${item.ip}</span></td>
                <td class="${item.isCF ? 'cf-true' : 'cf-false'}">${item.isCF ? 'true' : 'false'}</td>
                <td>${item.time ? item.time + 'ms' : '-'}</td>
            `;
            row.classList.add('fade-in');
            resultsBody.appendChild(row);
        }

        const hiddenCount = total - visibleCount;
        if (hiddenCount > 0 && !showAllResults) {
            hiddenCountSpan.textContent = String(hiddenCount);
            showMoreContainer.classList.remove('hidden');
        } else {
            showMoreContainer.classList.add('hidden');
        }
    }


    function copyAllToClipboard() {
        if (results.length === 0) return;
        const text = results.map(r => r.subdomain).join('\n');
        navigator.clipboard.writeText(text).then(() => {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => copyBtn.textContent = originalText, 2000);
        });
    }

    function exportToTxt() {
        if (results.length === 0) return;
        const text = results.map(r => `${r.subdomain} | ${r.ip} | ${r.isCF}`).join('\n');
        downloadFile(text, 'results.txt', 'text/plain');
    }

    function exportToJson() {
        if (results.length === 0) return;
        const json = JSON.stringify(results, null, 2);
        downloadFile(json, 'results.json', 'application/json');
    }

    function downloadFile(content, fileName, contentType) {
        const a = document.createElement('a');
        const file = new Blob([content], { type: contentType });
        a.href = URL.createObjectURL(file);
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(a.href);
    }
});
