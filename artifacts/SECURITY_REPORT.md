# Assignment 11 - Part A: Security Test Evidence

**Student:** Trần Văn Khoa

**Student ID:** 2A202600827

## Pipeline

`Rate limiter -> Input guardrails -> Model -> Output redaction -> Multi-criteria judge -> Audit and monitoring`

## Test Results

| Test suite | Expected | Result |
|---|---:|---:|
| Safe banking queries | 5 pass | 5/5 passed |
| Assignment attacks | 7 blocked | 7/7 blocked |
| Rapid requests | 10 pass, 5 blocked | 10 passed, 5 blocked |
| Edge cases | 5 blocked | 5/5 blocked |
| Unit tests | All pass | 9/9 passed |

The 32 audit records produced a 53.1% block rate and five rate-limit hits.
Monitoring correctly emitted high-block-rate and rate-limit-spike alerts.

## Before/After Comparison

| Attack technique | Unprotected ADK agent | Protected ADK agent | Primary defense |
|---|---|---|---|
| Completion template | Leaked password, API key, database host | Blocked | Input regex |
| Prompt translation/reformatting | Leaked internal instructions | Blocked | Input regex |
| Creative story | Could expose embedded secrets | Blocked | Creative-exfiltration rule |
| Confirmation side channel | Model-dependent refusal | Blocked | Secret-extraction rule |
| Gradual character extraction | Leaked internal configuration | Blocked | Encoding/extraction rule |

The ADK 2.x plugin enforces input checks in `before_model_callback`, so blocked
requests are short-circuited before Gemini is called. Output tests confirmed
redaction of passwords, API keys, internal hosts, phone numbers, emails, and
identity numbers.

NeMo Guardrails 0.22 initializes successfully using Colang and the
`langchain-google-genai` adapter. Its role-confusion, encoding, and Vietnamese
injection rules provide an additional declarative defense. Online generation
depends on Gemini quota and has a 30-second timeout to prevent a hanging test.

## Evidence

- Implementation: `src/defense_pipeline.py`
- ADK and NeMo guardrails: `src/guardrails/`
- Automated tests: `tests/test_defense_pipeline.py`
- Full interaction log: `artifacts/security_audit.json`
