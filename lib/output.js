'use strict';
// Output formatters: SARIF v2.1.0 + JUnit XML.
//
// SARIF is the format GitHub Code Scanning ingests. Each finding becomes a
// "result" with a rule reference. CI workflows can upload SARIF and have
// findings appear as annotations on PRs.
//
// JUnit XML is what most test runners speak (Jenkins, GitLab, generic CI
// dashboards). One <testcase> per finding category; failures = findings present.

const SEVERITY_TO_SARIF = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

function sarifLevel(sev) {
  return SEVERITY_TO_SARIF[sev] || 'note';
}

// Emit SARIF v2.1.0. One run per scan, one rule per unique finding category,
// one result per finding. Locations point at the URL that surfaced the
// finding (SARIF allows non-file artifactLocations).
function toSarif(reconResult, packageVersion) {
  const findings = reconResult.findings || [];
  // Build the rule registry keyed by `<category>:<title-slug>`.
  const ruleMap = new Map();
  for (const f of findings) {
    const slug = (f.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 60);
    const ruleId = `${f.category || 'misc'}/${slug}`;
    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.detail || f.title },
        defaultConfiguration: { level: sarifLevel(f.severity) },
        helpUri: 'https://uxcontinuum.com/vibe-audit',
        properties: { category: f.category || 'misc', severity: f.severity },
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'vibe-check-recon',
          version: packageVersion || 'unknown',
          informationUri: 'https://github.com/turleydesigns/vibe-check-recon',
          rules: [...ruleMap.values()],
        },
      },
      results: findings.map(f => {
        const slug = (f.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 60);
        return {
          ruleId: `${f.category || 'misc'}/${slug}`,
          level: sarifLevel(f.severity),
          message: { text: f.detail || f.title },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.url || reconResult.url },
            },
          }],
          properties: {
            severity: f.severity,
            remediation: f.remediation,
          },
        };
      }),
      invocations: [{
        executionSuccessful: reconResult.ok !== false,
        endTimeUtc: reconResult.scanned_at || new Date().toISOString(),
      }],
    }],
  };
}

function escXml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Emit JUnit XML. One <testsuite> per scan, one <testcase> per category we
// look at. A category with findings emits <failure> children. Empty
// categories emit clean testcases (signals "this category was checked and
// nothing surfaced"). CI runners report findings as test failures.
const CATEGORIES = [
  { id: 'data_exposure',   name: 'Data exposure' },
  { id: 'env_config',      name: 'Env / config' },
  { id: 'auth',            name: 'Auth & cookies' },
];

function toJUnitXml(reconResult, packageVersion) {
  const findings = reconResult.findings || [];
  const byCategory = {};
  for (const c of CATEGORIES) byCategory[c.id] = [];
  for (const f of findings) {
    const cat = byCategory[f.category];
    if (cat) cat.push(f);
  }
  const cases = CATEGORIES.map(c => {
    const items = byCategory[c.id];
    const failures = items.map(f => {
      const msg = `[${f.severity}] ${f.title}`;
      const body = `${f.detail || ''}\n${f.remediation ? 'Fix: ' + f.remediation : ''}\n${f.url || ''}`;
      return `      <failure type="${escXml(f.severity)}" message="${escXml(msg)}">${escXml(body)}</failure>`;
    }).join('\n');
    return `    <testcase classname="vibe-check-recon" name="${escXml(c.name)}" time="0">${failures ? '\n' + failures + '\n    ' : ''}</testcase>`;
  }).join('\n');
  const totalFailures = findings.length;
  const totalTests = CATEGORIES.length;
  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="vibe-check-recon" tests="${totalTests}" failures="${totalFailures}">
  <testsuite name="${escXml(reconResult.url || 'recon')}" tests="${totalTests}" failures="${totalFailures}" time="0" timestamp="${escXml(reconResult.scanned_at || new Date().toISOString())}">
${cases}
  </testsuite>
</testsuites>`;
}

module.exports = { toSarif, toJUnitXml, SEVERITY_TO_SARIF };
