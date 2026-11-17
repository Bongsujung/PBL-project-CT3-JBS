# Category 3: Cryptocurrency Platform Kubernetes Incident (2025)

[한국어](README.md) | **English**

## Real Incident

In a 2025 cryptocurrency-platform Kubernetes incident, an attacker used acquired workload ServiceAccount credentials to call the Kubernetes API, enumerate Secrets and resources, and attempt access to another workload. Kubernetes can project ServiceAccount tokens into Pods by default, making least-privilege RBAC important. See the [Kubernetes ServiceAccount documentation](https://kubernetes.io/docs/concepts/security/service-accounts/).

> This lab does not steal real Secrets or execute commands in another Pod. It safely simplifies the behavior by using one low-privilege ServiceAccount for both allowed baseline requests and denied attack-like requests.

Every script uses the same `pbl-crypto-platform-app` ServiceAccount. It can only `get/list` Pods, Services, and ConfigMaps; it cannot read Secrets or create `pods/exec`.

## Attack Mapping

| Script | Real attack phase | API behavior | Audit Log evidence |
| --- | --- | --- | --- |
| `normal.sh` | Normal application API use | Query pods/services/configmaps | Same user, `get/list`, `code=200` |
| `abnormal_1.sh` | Secret enumeration | `list` secrets | Same user, resource=secrets, `code=403` |
| `abnormal_2.sh` | Access another workload | `create` pods/exec | Same user, subresource=exec, `code=403` |
| `abnormal_3.sh` | Bulk resource enumeration | Repeated pods/secrets/configmaps queries | Same user, broader resources and sharply higher frequency |

## Run and Observe

Terminal 1:

```bash
docker exec pbl-security-control-plane \
  tail -F /var/log/kubernetes/audit.log | \
grep --line-buffered pbl-crypto-platform-app
```

Terminal 2:

```bash
cd pbl-project
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

See `logs/normal.log` and `logs/abnormal_1.log` through `abnormal_3.log` for representative events.

## Detection Lab

This lab separates normal use from attacks in the requests of one ServiceAccount. The only input is the Kubernetes audit log.

### Additional Scenarios

The provided scenarios do not show the false positives and false negatives of the rules. Thus, this lab adds four scenarios. They use the same ServiceAccount and Role as the provided scripts.

| Script | Real attack phase | API behavior | Audit Log evidence |
| --- | --- | --- | --- |
| `normal_2.sh` | Normal monitoring | `list` pods every 2 s, 30 times | Same user, periodic single-resource requests, `code=200` |
| `abnormal_4.sh` | Permission discovery | `kubectl auth can-i` ×3 (`create` selfsubjectrulesreviews, selfsubjectaccessreviews) | Same user, `code=201`, no 403 |
| `abnormal_5.sh` | Low-rate resource enumeration | Query pods/services/configmaps 6 times, 15 s apart | Same user, `code=200`, a maximum of 3 requests per 10 s |
| `abnormal_6.sh` | Enumeration of allowed resources | Query pods/services/configmaps 6 times without delay | Same user, `code=200`, sharply higher frequency |

### Run

Run all commands from the project root. Run one scenario at a time. Parallel runs mix the log segments.

```bash
# Run the scenarios and collect the logs (approximately 3 minutes)
./category3/detector/collect.sh all

# Detect and evaluate
python3 category3/detector/detect.py category3/results/raw/*.jsonl \
  --json category3/results/summary.json > category3/results/report.md
```

`collect.sh` records the line count of audit.log before and after each scenario. It saves the lines between the two counts in `results/raw/<scenario>.jsonl`. The file name prefix is the label (`normal*`: normal, `abnormal*`: attack). To collect one scenario, run `./category3/detector/collect.sh abnormal_4`.

You can also run the additional scenarios one by one:

```bash
./category3/normal_2.sh
./category3/abnormal_4.sh
./category3/abnormal_5.sh
./category3/abnormal_6.sh
```

`logs/normal_2.log` and `logs/abnormal_4.log` to `abnormal_6.log` contain example events. Each file contains the `ResponseComplete` events of the target ServiceAccount from the collected logs.

### Method

Preprocessing has three steps:

1. Keep the events where `user.username` is `system:serviceaccount:pbl-security:pbl-crypto-platform-app`. A search for the name string also finds administrator requests to this ServiceAccount (for example, `create token`).
2. Keep the events where `stage` is `ResponseComplete`. The second rule of the audit policy has no `omitStages`. Thus, the API server also records pods, services, and secrets requests at the `RequestReceived` stage.
3. Remove the discovery requests that have no `objectRef`.

The detector makes one decision for each session (log file, token JTI). Each script run gets a new token. Thus, one run is one session. If one or more enabled rules match, the session is an attack.

| ID | Attribute | Condition | Severity |
| --- | --- | --- | --- |
| D1 | Target | `resource = secrets` (any result) | High |
| D2 | Target | `subresource` is `exec`, `attach`, or `portforward` | High |
| D3 | Authorization | `decision = forbid` or `code = 403` | Medium |
| D4 | Rate | 10 s window: same (verb, resource) ≥ 3, or all requests ≥ 10 | Medium |
| D5 | Client | `userAgent` does not start with `kubectl/` | Low |
| D6 | Permission query | `resource` is `selfsubjectrulesreviews` or `selfsubjectaccessreviews` | Medium |
| D4' | Rate (variant) | 10 s window: same (verb, resource) ≥ 3 and resource types ≥ 2, or all requests ≥ 10 | Medium |

### Results

Each of the eight scenarios ran once on a kind v1.31 cluster (8 sessions: 2 normal, 6 attack).

| Set | Rules | TP | FP | FN | TN | Precision | Recall |
| --- | --- | :-: | :-: | :-: | :-: | :-: | :-: |
| A | D3 | 3 | 0 | 3 | 2 | 1.00 | 0.50 |
| B | D1–D5 | 4 | 1 | 2 | 1 | 0.80 | 0.67 |
| C | D1–D6 | 5 | 1 | 1 | 1 | 0.83 | 0.83 |
| D | D1–D6 without D4 | 4 | 0 | 2 | 2 | 1.00 | 0.67 |
| E | D1–D6 with D4 replaced by D4' | 5 | 0 | 1 | 2 | 1.00 | 0.83 |

| Scenario | Rules matched (set C) | Outcome |
| --- | --- | :-: |
| `normal.sh` | none | TN |
| `normal_2.sh` | D4 (5 repeats in a 10 s window) | FP |
| `abnormal_1.sh` | D1, D3 | TP |
| `abnormal_2.sh` | D2, D3, D5 | TP |
| `abnormal_3.sh` | D1, D3, D4 | TP |
| `abnormal_4.sh` | D6 | TP |
| `abnormal_5.sh` | none (a maximum of 3 requests per 10 s window) | FN |
| `abnormal_6.sh` | D4 | TP |

`results/report.md` contains the preprocessing counts, the D4 threshold test, and the evidence events (auditID) of each alert.

### Error Analysis and Limitations

- Preprocessing: The collected segments contain 838 events. 196 events contain the ServiceAccount name. In 170 of these events, the ServiceAccount is the actor. The other 26 are administrator requests, for example `get serviceaccounts` and `create token`. The duplicates are 72 `RequestReceived` events (pods 52, services 13, secrets 7) and 1 `ResponseStarted` event of `pods/exec`.
- False positive (`normal_2.sh`): Polling every 2 s puts 5 identical requests in a 10 s window. Thus, D4 matches. A repeat threshold of 6 or more removes the false positive. But this value comes from the test scenarios. Without D4 (set D), the false positive goes away, but the detector does not find `abnormal_6.sh`.
- False negative (`abnormal_5.sh`): A 10 s window contains a maximum of 3 requests. Thus, no rule matches. For each rate measure, a normal session has a larger value: repeats per window 1 (`normal.sh`: 2), requests per window 3 (`normal.sh`: 5), requests per session 18 (`normal_2.sh`: 30). Thus, a rate threshold that finds `abnormal_5.sh` also finds a normal session. For example, add a session-count condition (≥ 18) to set E. Then the false negative changes into a false positive of `normal_2.sh`.
- Limitations:
  - The same person designed the rules and the scenarios. We defined D4' after we saw the results.
  - The data has one ServiceAccount and 8 sessions.
  - The D5 baseline (`kubectl/`) is an assumption of this lab.
  - The Metadata level does not record response bodies (for example, `allowed` of access reviews).
  - Real Pod tokens rotate. Thus, one attack can split into more than one session.

### Artifacts

| Path | Content |
| --- | --- |
| `normal_2.sh`, `abnormal_4.sh`–`abnormal_6.sh` | Additional scenarios |
| `detector/collect.sh` | Scenario run and audit log segment collection |
| `detector/detect.py` | Preprocessing, sessions, rules, evaluation (Python standard library) |
| `logs/normal_2.log`, `logs/abnormal_4.log`–`abnormal_6.log` | Example events of the additional scenarios |
| `results/raw/` | 8 collected logs |
| `results/report.md`, `results/summary.json` | Detection report and summary |
