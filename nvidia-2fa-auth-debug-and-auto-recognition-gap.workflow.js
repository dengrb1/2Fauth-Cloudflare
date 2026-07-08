export const meta = {
  name: 'nvidia-2fa-auth-debug-and-auto-recognition-gap',
  description: 'Diagnose NVIDIA OTP add failure and design auto-recognition for otpauth/text inputs',
  phases: [
    { title: 'Repo scan', detail: 'Map OTP add, parse, validate, store, import, UI, and generation paths' },
    { title: 'Independent analyses', detail: 'Root cause, compatibility, NVIDIA inference, UI gap, persistence/import review' },
    { title: 'Adversarial review', detail: 'Refute or tighten findings against code evidence' },
    { title: 'Synthesis', detail: 'Produce implementation-oriented final report and next /goal' },
  ],
};

const REPORT_SCHEMA = {
  type: 'object',
  properties: {
    role: { type: 'string' },
    confirmedFacts: { type: 'array', items: { type: 'string' } },
    inferredConclusions: { type: 'array', items: { type: 'string' } },
    codeLocations: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          functionOrArea: { type: 'string' },
          linesOrSearchHint: { type: 'string' },
          relevance: { type: 'string' },
        },
        additionalProperties: false,
      },
    },
    failureConditions: { type: 'array', items: { type: 'string' } },
    recommendedChanges: { type: 'array', items: { type: 'string' } },
    verificationSteps: { type: 'array', items: { type: 'string' } },
    uncertainties: { type: 'array', items: { type: 'string' } },
  },
  additionalProperties: false,
};

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    confirmed: { type: 'array', items: { type: 'string' } },
    refutedOrWeakened: { type: 'array', items: { type: 'string' } },
    missingEvidence: { type: 'array', items: { type: 'string' } },
    strongerExplanation: { type: 'string' },
    mustVerifyManually: { type: 'array', items: { type: 'string' } },
  },
  additionalProperties: false,
};

const SYNTHESIS_SCHEMA = {
  type: 'object',
  properties: {
    executiveSummary: { type: 'array', items: { type: 'string' } },
    confirmedFindings: { type: 'array', items: { type: 'string' } },
    probableRootCause: { type: 'array', items: { type: 'string' } },
    affectedLocations: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          functionOrArea: { type: 'string' },
          evidence: { type: 'string' },
        },
        additionalProperties: false,
      },
    },
    nvidiaCompatibility: { type: 'array', items: { type: 'string' } },
    minimalFix: { type: 'array', items: { type: 'string' } },
    recommendedFix: { type: 'array', items: { type: 'string' } },
    autoRecognitionDesign: { type: 'array', items: { type: 'string' } },
    risksAndRegressionPoints: { type: 'array', items: { type: 'string' } },
    verificationChecklist: { type: 'array', items: { type: 'string' } },
    openQuestions: { type: 'array', items: { type: 'string' } },
    nextCodexGoal: { type: 'string' },
  },
  additionalProperties: false,
};

const sharedContext = `
You are analyzing a Cloudflare Worker repo in the current working directory.
User goal: diagnose why adding NVIDIA 2FA fails with "algorithm must be SHA-256 or SHA-512"; decide whether NVIDIA's OTP parameters are incompatible or repo logic is wrong; identify exact code paths; design auto-recognition for otpauth/text/secret inputs.
Repository hints: src/worker.js is the main Worker; migrations/ has D1 schema; README.md and wrangler.toml may document behavior.
Do not edit files. Use read-only commands only. Prefer rg for search. Cite function/area names and exact search hints or line numbers. Separate code-confirmed facts from protocol inference and manual verification gaps.
`;

phase('Repo scan');
const repoScan = await agent(`${sharedContext}
Map every relevant OTP code path. Find:
- add/manual routes and UI form handling
- otpauth URI parser(s)
- algorithm/digits/period/counter validation
- secret decode/normalize logic
- TOTP/HOTP generation logic
- imports/exports/encrypted backup and persistence fields
- any QR/text import or paste helper UI
Return precise code locations and how the paths connect.`, {
  label: 'repo-scan',
  sandbox: 'read-only',
  schema: REPORT_SCHEMA,
  timeoutMs: 600000,
});

phase('Independent analyses');
const analyses = await parallel([
  () => agent(`${sharedContext}
You are the root cause engineer. Using the repo scan below, trace the exact source of the error text "algorithm must be SHA-256 or SHA-512".
If the text comes from a dependency/web crypto API, keep tracing who supplied the rejected parameter.
Identify precise triggering conditions, input value, branch, and call chain from user action to throw.
Repo scan:
${JSON.stringify(repoScan)}`, {
    label: 'root-cause',
    sandbox: 'read-only',
    schema: REPORT_SCHEMA,
    timeoutMs: 600000,
  }),
  () => agent(`${sharedContext}
You are the OTP compatibility reviewer. Compare this repo's TOTP/HOTP/otpauth behavior with real-world otpauth URI conventions.
Focus on SHA1/SHA256/SHA512, algorithm aliases/case, digits, period, HOTP counter, issuer/label parsing, and base32 secret normalization.
State which limitations are bugs vs intentional policy choices, and which services besides NVIDIA could fail.
Repo scan:
${JSON.stringify(repoScan)}`, {
    label: 'otp-compat',
    sandbox: 'read-only',
    schema: REPORT_SCHEMA,
    timeoutMs: 600000,
  }),
  () => agent(`${sharedContext}
You are the NVIDIA scenario investigator. The repo may not include a sample NVIDIA URI.
From the error and code path, infer the most likely NVIDIA input shape and parameters, but label inference clearly.
Find where the system would reject a NVIDIA otpauth URI using SHA1/default SHA1 or other common NVIDIA parameters.
Report what can be confirmed from code and what needs manual verification with the user's actual NVIDIA QR/URI.
Repo scan:
${JSON.stringify(repoScan)}`, {
    label: 'nvidia-inference',
    sandbox: 'read-only',
    schema: REPORT_SCHEMA,
    timeoutMs: 600000,
  }),
  () => agent(`${sharedContext}
You are the product-minded UX engineer. Audit the embedded UI and add/import flows for content auto-recognition gaps.
Design a concrete recognizer covering complete otpauth:// URIs, plain text with secret/issuer/account/algorithm/digits/period/counter, TOTP vs HOTP detection, NVIDIA-style compatibility handling, errors, prompts, and fallback behavior.
Tie the design to likely functions or new helper functions in this codebase.
Repo scan:
${JSON.stringify(repoScan)}`, {
    label: 'auto-recognition',
    sandbox: 'read-only',
    schema: REPORT_SCHEMA,
    timeoutMs: 600000,
  }),
  () => agent(`${sharedContext}
You are the persistence/import/export reviewer. Check whether the D1 schema and import/export/encrypted backup paths can store and round-trip algorithm, digits, period, type, and HOTP counter safely.
Identify migration needs, backward compatibility concerns, and any data corruption or defaulting risks.
Repo scan:
${JSON.stringify(repoScan)}`, {
    label: 'storage-import',
    sandbox: 'read-only',
    schema: REPORT_SCHEMA,
    timeoutMs: 600000,
  }),
]);

phase('Adversarial review');
const adversarial = await agent(`${sharedContext}
You are the adversarial reviewer. Your job is to refute weak claims and force tighter evidence.
Review the repo scan and all independent analyses. Challenge especially:
- Is NVIDIA definitely SHA1, or only inferred?
- Is the thrown error really from code in this repo, Web Crypto, or a validation helper?
- Does the repo reject SHA1 at parsing time, storage time, or generation time?
- Are recommended fixes compatible with existing TOTP/HOTP records and exports?
- Is auto-recognition scoped to realistic inputs and safe error handling?
Return confirmed/refuted/missing evidence and the strongest explanation.
Repo scan:
${JSON.stringify(repoScan)}
Analyses:
${JSON.stringify(analyses)}`, {
  label: 'adversarial',
  sandbox: 'read-only',
  schema: REVIEW_SCHEMA,
  timeoutMs: 600000,
});

phase('Synthesis');
const synthesis = await agent(`${sharedContext}
Create the final engineering report in the user's requested structure:
1. Executive summary
2. Confirmed findings
3. Probable root cause
4. Recommended fix
5. Auto-recognition feature design
6. Verification checklist
7. Risks / open questions

Requirements:
- Distinguish code-confirmed facts, code/protocol inference, and manual verification needs.
- Include exact files and functions/areas.
- State precise error-triggering conditions.
- Explain why NVIDIA likely triggers and what other services could trigger.
- Compare minimal fix vs recommended fix.
- Include implementation-level design: parsing order, field mapping, exception handling, fallback strategy, target function list.
- Include a directly executable Codex /goal for implementation.

Repo scan:
${JSON.stringify(repoScan)}
Analyses:
${JSON.stringify(analyses)}
Adversarial review:
${JSON.stringify(adversarial)}`, {
  label: 'synthesis',
  sandbox: 'read-only',
  schema: SYNTHESIS_SCHEMA,
  timeoutMs: 900000,
});

return {
  repoScan,
  analyses,
  adversarial,
  synthesis,
};
