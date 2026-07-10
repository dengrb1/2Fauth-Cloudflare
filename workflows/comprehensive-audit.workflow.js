export const meta = {
  name: "comprehensive-audit",
  description: "Comprehensive security / functional audit for the 2Fauth Cloudflare Worker repo",
  phases: [
    { title: "Map", detail: "inventory attack surface, trust boundaries, and high-risk hotspots" },
    { title: "Hunt", detail: "parallel multi-lens discovery across auth, sessions, crypto, OTP, import/export, UI, and data integrity" },
    { title: "Verify", detail: "independent skeptics refute candidates by default; only survivors are kept" },
  ],
};

const REPO_NAME = (args && args.repoName) || "2Fauth-Cloudflare";
const TARGETS = (args && args.targets) || [
  "src/worker.js",
  "migrations/",
  "tests/worker-api.spec.js",
  "README.md",
  "API.md",
  "wrangler.toml",
  "wrangler.jsonc",
];
const MAX_FINDINGS_PER_LENS = (args && args.maxFindingsPerLens) || 6;
const MAX_VERIFY = (args && args.maxVerify) || 15;
const SKEPTICS = (args && args.skeptics) || 3;

const TARGET_TEXT = TARGETS.join(", ");

const MAP_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "hotspots", "trustBoundaries", "notes"],
  properties: {
    summary: { type: "string" },
    hotspots: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "why"],
        properties: {
          name: { type: "string" },
          why: { type: "string" },
        },
      },
    },
    trustBoundaries: {
      type: "array",
      items: { type: "string" },
    },
    notes: {
      type: "array",
      items: { type: "string" },
    },
  },
};

const FINDINGS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "kind",
          "category",
          "severity",
          "file",
          "line",
          "routeOrFunction",
          "claim",
          "evidence",
          "impact",
          "exploitOrFailure",
          "confidence",
        ],
        properties: {
          title: { type: "string" },
          kind: { type: "string", enum: ["security", "functional", "operational"] },
          category: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          file: { type: "string" },
          line: { type: "string" },
          routeOrFunction: { type: "string" },
          claim: { type: "string" },
          evidence: { type: "string" },
          impact: { type: "string" },
          exploitOrFailure: { type: "string" },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
        },
      },
    },
  },
};

const VERDICT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["refuted", "reason", "supportingEvidence", "counterEvidence"],
  properties: {
    refuted: { type: "boolean" },
    reason: { type: "string" },
    supportingEvidence: { type: "string" },
    counterEvidence: { type: "string" },
  },
};

const MAP_PROMPTS = [
  {
    key: "surface",
    prompt:
      `Audit target: ${REPO_NAME}. Read ${TARGET_TEXT}. ` +
      `Map the external surface: auth entry points, bootstrap/setup flow, unauthenticated routes, state-changing routes, admin-only capabilities, import/export paths, and machine-client API surfaces. ` +
      `Summarize the attack surface and identify the highest-risk hotspots by name.`,
  },
  {
    key: "trust",
    prompt:
      `Audit target: ${REPO_NAME}. Read ${TARGET_TEXT}. ` +
      `Map trust boundaries and security assumptions: sessions/cookies, refresh rotation, bearer/API tokens, encryption key use, CORS/CSRF model, OTP secret handling, D1 persistence assumptions, and background cleanup paths. ` +
      `Call out what absolutely must hold true for the system to stay secure/correct.`,
  },
  {
    key: "failure",
    prompt:
      `Audit target: ${REPO_NAME}. Read ${TARGET_TEXT}. ` +
      `Map likely failure hotspots for a deep code audit: places where one bug could cause auth bypass, privilege escalation, OTP desync, secret disclosure, mass data corruption, or persistent lockout. ` +
      `Name the specific functions/routes/components and why they deserve adversarial review.`,
  },
];

const LENSES = [
  {
    key: "authz",
    focus:
      "authentication, authorization, bootstrap abuse, RBAC enforcement, privilege escalation, route-level guard omissions, admin/user separation",
  },
  {
    key: "session",
    focus:
      "web sessions, mobile/api/extension bearer sessions, refresh rotation, fixation, replay, logout invalidation, TTL refresh, token hashing, last-used updates",
  },
  {
    key: "cors-csrf",
    focus:
      "CORS allowlist, credentialed requests, CSRF exposure, preflight logic, origin validation, browser extension trust model, unsafe cross-origin assumptions",
  },
  {
    key: "crypto-export",
    focus:
      "encryption/decryption, encrypted backup, plaintext export, secret handling, passphrase derivation, key misuse, sensitive data leakage in responses/errors/logs",
  },
  {
    key: "otp",
    focus:
      "TOTP/HOTP correctness, counter/time-window handling, verification semantics, race conditions when consuming HOTP, disabled entries, algorithm/digits/period normalization",
  },
  {
    key: "import-export",
    focus:
      "JSON import/export, otpauth import/export, malformed input handling, overwrite semantics, trust of imported metadata, group linkage, duplicate handling, destructive edge cases",
  },
  {
    key: "input-validation",
    focus:
      "request parsing, path/body/query validation, ID normalization, integer bounds, unexpected null/empty values, oversized input handling, unsafe defaults, parsing ambiguity",
  },
  {
    key: "ui-xss",
    focus:
      "embedded HTML/UI generation, HTML escaping, reflected/stored XSS, DOM injection via data fields, error detail exposure, unsafe rendering of user-controlled values",
  },
  {
    key: "data-integrity",
    focus:
      "D1 schema/migrations, uniqueness/foreign-key assumptions, race windows, cleanup jobs, session revocation consistency, delete cascades, orphaned records, partial-write states",
  },
  {
    key: "availability",
    focus:
      "恶性 BUG / high-severity correctness failures: runtime crashes, undefined behavior, inconsistent control flow, missing tables/columns compatibility bugs, lockouts, denial-of-service primitives",
  },
];

const VERIFY_ROLES = [
  {
    key: "controlflow",
    brief:
      "trace the real control flow and look for guards, early returns, hidden invariants, or role checks that disprove the claim",
  },
  {
    key: "reachability",
    brief:
      "test whether a realistic caller/attacker can actually reach the state and whether the stated impact is materially real",
  },
  {
    key: "state",
    brief:
      "check storage/session/OTP/crypto side-effects and search for code elsewhere in the repo that invalidates or mitigates the claim",
  },
];

function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

function confidenceRank(confidence) {
  return { high: 0, medium: 1, low: 2 }[confidence] ?? 3;
}

function findingKey(finding) {
  return [
    (finding.file || "").trim(),
    (finding.line || "").trim(),
    (finding.routeOrFunction || "").trim().toLowerCase(),
    (finding.title || "").trim().toLowerCase().slice(0, 120),
  ].join("::");
}

function compactMapSummary(mapResult, idx) {
  const hotspots = (mapResult.hotspots || [])
    .slice(0, 6)
    .map((h) => `${h.name}: ${h.why}`)
    .join(" | ");
  const trust = (mapResult.trustBoundaries || []).slice(0, 6).join(" | ");
  const notes = (mapResult.notes || []).slice(0, 6).join(" | ");
  return `MAP ${idx + 1}: ${mapResult.summary}\nHotspots: ${hotspots}\nTrust boundaries: ${trust}\nNotes: ${notes}`;
}

phase("Map");
const mapResults = (
  await parallel(
    MAP_PROMPTS.map((item) => () =>
      agent(item.prompt, {
        schema: MAP_SCHEMA,
        label: `map:${item.key}`,
        phase: "Map",
        sandbox: "read-only",
      }),
    ),
  )
).filter(Boolean);

const mapSummaryText = mapResults.map((m, idx) => compactMapSummary(m, idx)).join("\n\n");

phase("Hunt");
const huntResults = await parallel(
  LENSES.map((lens) => () =>
    agent(
      `Repository: ${REPO_NAME}. Audit targets: ${TARGET_TEXT}.\n\n` +
        `Context maps from separate reviewers:\n${mapSummaryText}\n\n` +
        `Your lens: ${lens.key}.\n` +
        `Focus on: ${lens.focus}.\n\n` +
        `Task:\n` +
        `1. Read the real code and tests, not just comments.\n` +
        `2. Find only concrete issues: security flaws, functional vulnerabilities, or severe correctness bugs.\n` +
        `3. Prefer issues with a trigger path, exploit path, or realistic failure scenario.\n` +
        `4. Ignore style, nits, and speculative concerns with no code evidence.\n` +
        `5. Report at most ${MAX_FINDINGS_PER_LENS} highest-signal findings.\n` +
        `6. Use exact file and line/range when you can; use '?' only if the location truly spans many places.\n` +
        `7. Be adversarial: assume hidden bugs exist in auth/session/OTP/import/export/error/cors edge cases.\n`,
      {
        schema: FINDINGS_SCHEMA,
        label: `hunt:${lens.key}`,
        phase: "Hunt",
        sandbox: "read-only",
      },
    ).then((result) => ({
      lens: lens.key,
      findings: (result && result.findings) || [],
    })),
  ),
);

const merged = new Map();
let rawFindings = 0;
for (const result of huntResults.filter(Boolean)) {
  for (const finding of result.findings || []) {
    if (!finding) continue;
    rawFindings++;
    const key = findingKey(finding);
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...finding,
        lenses: [result.lens],
        mentionCount: 1,
      });
      continue;
    }
    existing.mentionCount += 1;
    if (!existing.lenses.includes(result.lens)) existing.lenses.push(result.lens);
    if (severityRank(finding.severity) < severityRank(existing.severity)) existing.severity = finding.severity;
    if (confidenceRank(finding.confidence) < confidenceRank(existing.confidence)) existing.confidence = finding.confidence;
    if ((finding.evidence || "").length > (existing.evidence || "").length) existing.evidence = finding.evidence;
    if ((finding.impact || "").length > (existing.impact || "").length) existing.impact = finding.impact;
    if ((finding.exploitOrFailure || "").length > (existing.exploitOrFailure || "").length) existing.exploitOrFailure = finding.exploitOrFailure;
  }
}

const prioritized = [...merged.values()]
  .sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity) ||
    confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
    (b.mentionCount || 0) - (a.mentionCount || 0),
  )
  .slice(0, MAX_VERIFY);

log(`hunt complete: ${rawFindings} raw finding(s), ${merged.size} unique, ${prioritized.length} sent to verification`);

phase("Verify");
const verified = await parallel(
  prioritized.map((finding) => () =>
    parallel(
      VERIFY_ROLES.slice(0, SKEPTICS).map((role, idx) => () =>
        agent(
          `Repository: ${REPO_NAME}. Audit targets: ${TARGET_TEXT}.\n\n` +
            `Candidate finding:\n${JSON.stringify(finding, null, 2)}\n\n` +
            `You are skeptic #${idx + 1} (${role.key}). ${role.brief}.\n` +
            `Read the actual code path. Try to REFUTE this finding. If you cannot convince yourself it is real, default to refuted=true.\n` +
            `If the finding survives, explain the strongest supporting evidence. If it fails, explain the code path that invalidates it.\n`,
          {
            schema: VERDICT_SCHEMA,
            label: `verify:${finding.file}:${finding.line}`,
            phase: "Verify",
            sandbox: "read-only",
          },
        ),
      ),
    ).then((votes) => {
      const actualVotes = votes.filter(Boolean);
      const refutedVotes = actualVotes.filter((vote) => vote.refuted).length;
      const majority = Math.floor(actualVotes.length / 2) + 1;
      return {
        ...finding,
        votes: actualVotes,
        skeptics: actualVotes.length,
        refutedVotes,
        survives: refutedVotes < majority,
      };
    }),
  ),
);

const confirmed = verified
  .filter(Boolean)
  .filter((item) => item.survives)
  .sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity) ||
    confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
    (b.mentionCount || 0) - (a.mentionCount || 0),
  );

const refuted = verified
  .filter(Boolean)
  .filter((item) => !item.survives)
  .sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity) ||
    confidenceRank(a.confidence) - confidenceRank(b.confidence),
  );

return {
  repoName: REPO_NAME,
  targets: TARGETS,
  rawFindings,
  uniqueFindings: merged.size,
  verifiedCandidates: prioritized.length,
  confirmedFindings: confirmed.length,
  maps: mapResults,
  confirmed,
  refuted,
};
