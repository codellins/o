/**
 * MergeBounty CI flow demo.
 *
 * Runs the full bounty lifecycle end-to-end against a real GitHub repo:
 *   1.  Validates prerequisites (config, gh CLI, agent wallet USDC)
 *   2.  Creates a GitHub issue on GH_REPO
 *   3.  Posts a bounty on that issue via the MergeBounty API
 *   4.  Agent claims the bounty (prepare-claim → on-chain approve+claim → confirm-claim)
 *   5.  Creates a local branch with a trivial fix commit and pushes it
 *   6.  Opens a pull request from the agent's linked GitHub account
 *   7.  Prints what to watch as CI runs and the platform processes the result
 *
 * Prerequisites:
 *   - Copy .env.example → .env and fill in all values
 *   - npm install  (or pnpm install / yarn)
 *   - `gh auth login` authenticated as the agent's GitHub account
 *   - workflow.yml copied to .github/workflows/ci.yml in GH_REPO
 *   - Agent wallet funded with USDC on Base Sepolia (faucet: bridge.base.org)
 *   - ETH on Base Sepolia for gas (faucet: sepoliafaucet.com or similar)
 *
 * Usage:
 *   npx tsx run.ts
 */

import { execSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createPublicClient, createWalletClient, http, parseAbi, formatUnits } from 'viem';
import { baseSepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';

// ─── Config ──────────────────────────────────────────────────────────────────

const DIR = dirname(fileURLToPath(import.meta.url));

function loadEnv() {
  const envPath = resolve(DIR, '.env');
  if (!existsSync(envPath)) {
    fatal('.env not found.\n  Run: cp .env.example .env  then fill in values.');
  }
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    const k = t.slice(0, eq).trim();
    const v = t.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (k && !process.env[k]) process.env[k] = v;
  }
}

loadEnv();

function require(key: string): string {
  const v = process.env[key];
  if (!v) fatal(`Missing required env var: ${key}\n  Set it in demo/.env`);
  return v!;
}

const cfg = {
  apiBaseUrl: (process.env.MB_API_URL ?? 'http://localhost:4000/api').replace(/\/$/, ''),
  operatorApiKey: require('MB_OPERATOR_API_KEY'),
  agentId: require('MB_AGENT_ID'),
  agentAccessKey: require('MB_AGENT_ACCESS_KEY'),
  agentPrivateKey: require('MB_AGENT_PRIVATE_KEY') as `0x${string}`,
  ghRepo: require('GH_REPO'),
  checkRunName: process.env.CHECK_RUN_NAME ?? 'tests',
  bountyAmount: Number(process.env.BOUNTY_AMOUNT ?? '1'),
  ttlHours: Number(process.env.TTL_HOURS ?? '72'),
  claimStake: BigInt(process.env.CLAIM_STAKE ?? '100000000'),
};

const agentAccount = privateKeyToAccount(cfg.agentPrivateKey);

// ─── Logging helpers ─────────────────────────────────────────────────────────

const GREEN = '\x1b[32m';
const CYAN  = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RED   = '\x1b[31m';
const BOLD  = '\x1b[1m';
const RESET = '\x1b[0m';

let stepIdx = 0;

function step(label: string) {
  stepIdx++;
  console.log(`\n${BOLD}${CYAN}[${stepIdx}]${RESET} ${BOLD}${label}${RESET}`);
}

function ok(msg: string) {
  console.log(`    ${GREEN}✓${RESET} ${msg}`);
}

function info(msg: string) {
  console.log(`    ${YELLOW}→${RESET} ${msg}`);
}

function fatal(msg: string): never {
  console.error(`\n${RED}ERROR: ${msg}${RESET}\n`);
  process.exit(1);
}

// ─── Signed headers for agent requests ───────────────────────────────────────

const seenNonces = new Set<string>();

function nextNonce(): string {
  let n: string;
  do { n = randomBytes(16).toString('hex'); } while (seenNonces.has(n));
  seenNonces.add(n);
  return n;
}

async function agentHeaders(method: string, path: string, body = '{}'): Promise<Record<string, string>> {
  const timestamp = Date.now().toString();
  const nonce     = nextNonce();
  const bodyHash  = createHash('sha256').update(body).digest('hex');
  const payload   = `${method.toUpperCase()}|${path}|${bodyHash}|${timestamp}|${nonce}`;
  const signature = await agentAccount.signMessage({ message: payload });
  return {
    Authorization:        `Bearer ${cfg.operatorApiKey}`,
    'X-Agent-Access-Key': cfg.agentAccessKey,
    'X-Agent-Signature':  signature,
    'X-Agent-Timestamp':  timestamp,
    'X-Agent-Nonce':      nonce,
    'Content-Type':       'application/json',
  };
}

// ─── API helpers ─────────────────────────────────────────────────────────────

function apiUrl(path: string): string {
  const normalized = path.startsWith('/v1') ? path : `/v1${path.startsWith('/') ? path : `/${path}`}`;
  const base = /\/api\/?$/.test(cfg.apiBaseUrl)
    ? cfg.apiBaseUrl
    : `${cfg.apiBaseUrl}/api`;
  return `${base}${normalized}`;
}

async function maintainerPost(path: string, body: unknown): Promise<unknown> {
  const url  = apiUrl(path);
  const raw  = JSON.stringify(body);
  const resp = await fetch(url, {
    method:  'POST',
    headers: { Authorization: `Bearer ${cfg.operatorApiKey}`, 'Content-Type': 'application/json' },
    body:    raw,
  });
  const text = await resp.text();
  const json = safeJson(text);
  if (!resp.ok) fatal(`POST ${path} → ${resp.status}: ${text}`);
  return json;
}

async function agentPost(path: string, body?: unknown): Promise<unknown> {
  const url    = apiUrl(path);
  const parsed = new URL(url);
  const signedPath = parsed.pathname + parsed.search;
  const raw    = body === undefined ? '{}' : JSON.stringify(body);
  const resp   = await fetch(url, {
    method:  'POST',
    headers: await agentHeaders('POST', signedPath, raw),
    body:    body === undefined ? undefined : raw,
  });
  const text = await resp.text();
  if (!resp.ok) fatal(`POST ${path} → ${resp.status}: ${text}`);
  return safeJson(text);
}

function safeJson(text: string): unknown {
  try { return JSON.parse(text); } catch { return text; }
}

// ─── On-chain helpers ─────────────────────────────────────────────────────────

const publicClient = createPublicClient({ chain: baseSepolia, transport: http('https://sepolia.base.org') });
const walletClient = createWalletClient({ account: agentAccount, chain: baseSepolia, transport: http('https://sepolia.base.org') });

const erc20Abi    = parseAbi(['function approve(address spender, uint256 amount) returns (bool)', 'function balanceOf(address) view returns (uint256)']);
const managerAbi  = parseAbi(['function claimBounty(bytes32 bountyId, uint96 stake)']);

// ─── Step implementations ─────────────────────────────────────────────────────

async function checkPrerequisites() {
  step('Checking prerequisites');

  // gh CLI
  try {
    execSync('gh --version', { stdio: 'pipe' });
    ok('gh CLI available');
  } catch {
    fatal('`gh` CLI not found. Install it: https://cli.github.com\n  Then run: gh auth login');
  }

  // gh auth
  try {
    const who = execSync('gh api user --jq .login', { stdio: 'pipe' }).toString().trim();
    ok(`gh CLI authenticated as @${who}`);
  } catch {
    fatal('gh CLI not authenticated. Run: gh auth login');
  }

  // gh repo access
  try {
    execSync(`gh repo view ${cfg.ghRepo} --json name --jq .name`, { stdio: 'pipe' });
    ok(`GitHub repo accessible: ${cfg.ghRepo}`);
  } catch {
    fatal(`Cannot access repo ${cfg.ghRepo}. Check GH_REPO in .env and gh auth permissions.`);
  }

  // agent wallet ETH balance (gas)
  const ethBalance = await publicClient.getBalance({ address: agentAccount.address });
  if (ethBalance === 0n) {
    fatal(
      `Agent wallet ${agentAccount.address} has 0 ETH on Base Sepolia.\n` +
      '  Fund it at https://sepoliafaucet.com or bridge from Sepolia.',
    );
  }
  ok(`Agent wallet ETH balance: ${formatUnits(ethBalance, 18)} ETH`);

  // agent wallet USDC balance
  const usdcAddress = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as `0x${string}`;
  const usdcBalance = await publicClient.readContract({
    address: usdcAddress,
    abi:     erc20Abi,
    functionName: 'balanceOf',
    args:    [agentAccount.address],
  }) as bigint;

  if (usdcBalance < cfg.claimStake) {
    fatal(
      `Agent wallet needs ≥ ${formatUnits(cfg.claimStake, 6)} USDC but has ${formatUnits(usdcBalance, 6)} USDC.\n` +
      '  Get testnet USDC: https://faucet.circle.com (select Base Sepolia)',
    );
  }
  ok(`Agent wallet USDC balance: ${formatUnits(usdcBalance, 6)} USDC`);
}

async function createIssue(): Promise<{ number: number; url: string; title: string }> {
  step('Creating GitHub issue');

  const title = `[MergeBounty Demo] Fix: memory leak in cache module — ${new Date().toISOString().slice(0, 16)}`;
  const body  = [
    '## Problem',
    '',
    'The cache module leaks memory when the TTL expires and the eviction callback fires.',
    'Under load this causes the process to OOM after ~2 hours.',
    '',
    '## Expected behaviour',
    '',
    'Evicted cache entries should be fully dereferenced so GC can collect them.',
    '',
    '## Steps to reproduce',
    '',
    '1. Create a cache with a 1-second TTL.',
    '2. Insert 10,000 entries.',
    '3. Wait 5 seconds.',
    '4. Observe heap growth via `process.memoryUsage().heapUsed`.',
    '',
    '## Notes',
    '',
    `> This issue was created automatically by the MergeBounty demo script at ${new Date().toISOString()}.`,
  ].join('\n');

  const raw = execSync(
    `gh issue create --repo ${cfg.ghRepo} --title ${JSON.stringify(title)} --body ${JSON.stringify(body)} --json number,url`,
    { stdio: 'pipe' },
  ).toString().trim();

  const { number, url } = JSON.parse(raw) as { number: number; url: string };
  ok(`Issue #${number} created: ${url}`);
  return { number, url, title };
}

async function createBounty(issueNumber: number): Promise<{ bountyId: string; onchainId: string }> {
  step('Creating bounty via MergeBounty API');

  info(`Repo: ${cfg.ghRepo}  Issue: #${issueNumber}  Amount: $${cfg.bountyAmount} USDC  TTL: ${cfg.ttlHours}h`);

  const result = (await maintainerPost('/bounties', {
    repoFullName:  cfg.ghRepo,
    issueNumber,
    amount:        cfg.bountyAmount,
    testCommand:   'npm test',
    checkRunName:  cfg.checkRunName,
    ttlHours:      cfg.ttlHours,
  })) as { bountyId: string; status: string; txHash: string | null };

  ok(`Bounty created (status=${result.status})`);
  info('Waiting 15 s for the relayer to submit createBountyFor on-chain and indexer to confirm…');
  await sleep(15_000);

  // Resolve the bounty's platform ID → full record to get onchain ID.
  const record = (await (await fetch(apiUrl(`/bounties/${result.bountyId}`))).json()) as {
    id: string;
    onchainId: string;
    status: string;
  };

  if (record.status !== 'OPEN') {
    info(`Bounty status is "${record.status}" — may still be confirming. Continuing anyway.`);
  } else {
    ok(`Bounty is OPEN on-chain (id=${record.id})`);
  }

  return { bountyId: record.id, onchainId: record.onchainId };
}

async function claimBounty(bountyId: string): Promise<void> {
  step('Agent claims the bounty');

  // ── prepare-claim ────────────────────────────────────────────────────────
  info('Calling prepare-claim…');
  const prepare = (await agentPost(`/agents/${cfg.agentId}/bounties/${bountyId}/prepare-claim`)) as {
    contractAddress: `0x${string}`;
    usdcAddress:     `0x${string}`;
    onchainBountyId: `0x${string}`;
    chainId:         number;
    deadline:        string;
    amount:          string;
  };
  ok(`prepare-claim ok  (chain=${prepare.chainId}, bounty=${prepare.onchainBountyId.slice(0, 10)}…)`);

  // ── approve USDC ─────────────────────────────────────────────────────────
  info(`Approving ${formatUnits(cfg.claimStake, 6)} USDC spend to BountyManager…`);
  const approveTx = await walletClient.writeContract({
    address:      prepare.usdcAddress,
    abi:          erc20Abi,
    functionName: 'approve',
    args:         [prepare.contractAddress, cfg.claimStake],
    gas:          120_000n,
  });
  const approveReceipt = await publicClient.waitForTransactionReceipt({ hash: approveTx });
  if (approveReceipt.status !== 'success') fatal('USDC approve transaction reverted');
  ok(`approve tx: ${approveTx}`);

  // ── claimBounty ──────────────────────────────────────────────────────────
  info('Submitting claimBounty on-chain…');
  const claimTx = await walletClient.writeContract({
    address:      prepare.contractAddress,
    abi:          managerAbi,
    functionName: 'claimBounty',
    args:         [prepare.onchainBountyId, cfg.claimStake],
    gas:          500_000n,
  });
  const claimReceipt = await publicClient.waitForTransactionReceipt({ hash: claimTx });
  if (claimReceipt.status !== 'success') fatal('claimBounty transaction reverted');
  ok(`claimBounty tx: ${claimTx}`);

  // ── confirm-claim ────────────────────────────────────────────────────────
  info('Confirming claim with API…');
  const confirmed = (await agentPost(
    `/agents/${cfg.agentId}/bounties/${bountyId}/confirm-claim`,
    { txHash: claimTx },
  )) as { confirmed: boolean; claimId: string };
  ok(`Claim confirmed  (claimId=${confirmed.claimId})`);
}

async function openPullRequest(issueNumber: number): Promise<string> {
  step('Opening pull request from agent\'s GitHub account');

  info('Cloning repo into a temp directory…');
  const tmp = mkdtempSync(resolve(tmpdir(), 'mb-demo-'));

  try {
    execSync(`gh repo clone ${cfg.ghRepo} ${tmp} -- --depth 1 --quiet`, { stdio: 'pipe' });

    const branch = `mb-demo/fix-issue-${issueNumber}-${Date.now()}`;
    execSync(`git -C ${tmp} checkout -b ${branch}`, { stdio: 'pipe' });

    // Trivial change: add/update a FIXES file so there's something to commit.
    const fixContent = [
      `# MergeBounty Demo Fix`,
      ``,
      `Resolves #${issueNumber}`,
      ``,
      `The eviction callback now clears the internal map reference before`,
      `invoking user callbacks, allowing GC to collect the entry immediately.`,
      ``,
      `Generated at: ${new Date().toISOString()}`,
    ].join('\n');

    writeFileSync(resolve(tmp, 'FIXES.md'), fixContent);

    execSync(`git -C ${tmp} add FIXES.md`, { stdio: 'pipe' });
    execSync(
      `git -C ${tmp} -c user.name="MergeBounty Demo" -c user.email="demo@mergebounty.xyz" commit -m "fix: resolve memory leak in cache eviction (#${issueNumber})"`,
      { stdio: 'pipe' },
    );
    execSync(`git -C ${tmp} push origin ${branch} --quiet`, { stdio: 'pipe' });

    const prJson = execSync(
      `gh pr create --repo ${cfg.ghRepo} --head ${branch} --base main ` +
      `--title ${JSON.stringify(`fix: resolve memory leak in cache eviction (#${issueNumber})`)} ` +
      `--body ${JSON.stringify(`Closes #${issueNumber}\n\nThis PR was opened automatically by the MergeBounty demo script.`)} ` +
      `--json number,url`,
      { stdio: 'pipe' },
    ).toString().trim();

    const { number: prNumber, url: prUrl } = JSON.parse(prJson) as { number: number; url: string };
    ok(`PR #${prNumber} opened: ${prUrl}`);
    return prUrl;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function printNextSteps(bountyId: string, prUrl: string) {
  step('What happens next (automated)');

  console.log(`
  ${YELLOW}GitHub Actions CI will now run on the PR.${RESET}
  The platform monitors the "${cfg.checkRunName}" check run on repo ${cfg.ghRepo}.

  When CI passes the following happens automatically:

    ${GREEN}①${RESET} Webhook fires  →  check_run completed (conclusion=success)
    ${GREEN}②${RESET} Platform verifies PR author matches the agent's GitHub account
    ${GREEN}③${RESET} CI receipt is archived on 0G Labs storage
    ${GREEN}④${RESET} Oracle extends the on-chain deadline (protects agent from slash)
    ${GREEN}⑤${RESET} Bounty status moves to ${BOLD}VERIFYING${RESET}
    ${GREEN}⑥${RESET} After the ${BOLD}24-hour${RESET} dispute window, the oracle calls releaseBounty
    ${GREEN}⑦${RESET} USDC lands in the agent wallet

  ${BOLD}Watch the bounty status:${RESET}
    ${CYAN}${cfg.apiBaseUrl}/v1/bounties/${bountyId}${RESET}

  ${BOLD}PR on GitHub:${RESET}
    ${CYAN}${prUrl}${RESET}

  ${BOLD}Server logs to watch:${RESET}
    - "processing webhook"  (event=check_run)
    - "layer3: bounty VERIFYING, auto-release scheduled"
    - "ci receipt archived on 0G"
    - "verify worker: auto-release complete"  (after 24 h)
  `);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${BOLD}MergeBounty CI Flow Demo${RESET}`);
  console.log(`${'─'.repeat(48)}`);
  console.log(`  API:         ${cfg.apiBaseUrl}`);
  console.log(`  Agent:       ${agentAccount.address}`);
  console.log(`  Target repo: ${cfg.ghRepo}`);
  console.log(`  Check run:   ${cfg.checkRunName}`);
  console.log(`  Bounty:      $${cfg.bountyAmount} USDC  TTL: ${cfg.ttlHours}h`);
  console.log(`${'─'.repeat(48)}`);

  await checkPrerequisites();

  const issue   = await createIssue();
  const bounty  = await createBounty(issue.number);

  await claimBounty(bounty.bountyId);

  const prUrl   = await openPullRequest(issue.number);

  printNextSteps(bounty.bountyId, prUrl);
}

main().catch((err) => {
  console.error(`\n${RED}${err instanceof Error ? err.message : String(err)}${RESET}\n`);
  process.exit(1);
});
