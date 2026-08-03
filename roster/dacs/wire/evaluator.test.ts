import assert from "node:assert/strict";
import test from "node:test";
import { EvalBot } from "../../evalbot/evalbot.js";
import { securityAuditEvaluationPolicy } from "./evaluator.js";

const vulnerable = [{
  path: "server.js",
  content: "const command = req.query.cmd;\nexec(command, (_error, stdout) => res.end(stdout));\n",
}];

test("security audit evaluation rejects a well-formed report that omits a reproduced finding", async () => {
  const policy = securityAuditEvaluationPolicy(vulnerable);
  const ruling = await new EvalBot({ useLlm: false, predicates: policy.predicates }).evaluate({
    jobId: "missing-command-injection",
    rubric: policy.rubric,
    deliverable: { content: JSON.stringify({ seal: { bodyHash: "x" }, findings: [], padding: "x".repeat(100) }) },
  });
  assert.equal(ruling.verdict, "reject");
  assert.match(ruling.perCriterion.find((row) => row.criterionId === "deterministic-coverage")?.reason ?? "", /omits 1\/1/);
});

test("security audit evaluation accepts a report covering the reproduced finding", async () => {
  const policy = securityAuditEvaluationPolicy(vulnerable);
  const ruling = await new EvalBot({ useLlm: false, predicates: policy.predicates }).evaluate({
    jobId: "covered-command-injection",
    rubric: policy.rubric,
    deliverable: { content: JSON.stringify({
      seal: { bodyHash: "x" },
      findings: [{ ruleId: "code-exec-dynamic-argument", file: "server.js", line: 2 }],
      padding: "x".repeat(100),
    }) },
  });
  assert.equal(ruling.verdict, "accept");
});
