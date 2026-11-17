# Category 3: Cryptocurrency Platform Kubernetes Incident (2025)

**한국어** | [English](README_EN.md)

## 실제 사례

2025년 암호화폐 플랫폼 Kubernetes 침해 사례에서는 workload에서 획득한 ServiceAccount credential로 Kubernetes API를 호출하고, Secret과 리소스를 열거한 뒤 다른 workload 접근을 시도하는 post-compromise 흐름이 확인됐습니다. Kubernetes에서는 Pod에 ServiceAccount token이 기본적으로 투영될 수 있으므로 최소 권한 RBAC가 중요합니다. 동작 원리는 [Kubernetes ServiceAccount 문서](https://kubernetes.io/docs/concepts/security/service-accounts/)를 참고합니다.

> 이 실습은 실제 Secret을 탈취하거나 다른 Pod에 명령을 실행하지 않습니다. 동일한 저권한 ServiceAccount가 허용된 조회와 거부되는 공격성 요청을 보내도록 안전하게 단순화합니다.

모든 스크립트는 동일한 `pbl-crypto-platform-app` ServiceAccount를 사용합니다. 이 계정은 Pods, Services, ConfigMaps의 `get/list`만 허용되고 Secrets 및 `pods/exec` 권한은 없습니다.

## 공격 행위 대응

| 스크립트 | 실제 공격 단계 | API 행위 | Audit Log 관찰점 |
| --- | --- | --- | --- |
| `normal.sh` | 정상 애플리케이션 API 사용 | pods/services/configmaps 조회 | 같은 사용자, `get/list`, `code=200` |
| `abnormal_1.sh` | Secret enumeration | secrets `list` | 같은 사용자, resource=secrets, `code=403` |
| `abnormal_2.sh` | 다른 workload 접근 | pods/exec `create` | 같은 사용자, subresource=exec, `code=403` |
| `abnormal_3.sh` | 대량 resource enumeration | pods/secrets/configmaps 반복 조회 | 같은 사용자, resource 다양화와 빈도 급증 |

## 실행 및 로그

터미널 1:

```bash
docker exec pbl-security-control-plane \
  tail -F /var/log/kubernetes/audit.log | \
grep --line-buffered pbl-crypto-platform-app
```

터미널 2:

```bash
cd pbl-project
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

최근 이벤트:

```bash
docker exec pbl-security-control-plane \
  grep 'pbl-crypto-platform-app' /var/log/kubernetes/audit.log | tail -n 50
```

예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.

## 탐지 실습

같은 ServiceAccount의 요청에서 정상 사용과 공격을 구분합니다. 입력은 Audit Log만 사용합니다.

### 추가 시나리오

기본 시나리오만으로는 규칙의 오탐과 미탐을 확인할 수 없습니다. 그래서 시나리오 4개를 추가했습니다. 추가 시나리오는 기본 스크립트와 같은 ServiceAccount와 Role을 사용합니다.

| 스크립트 | 실제 공격 단계 | API 행위 | Audit Log 관찰점 |
| --- | --- | --- | --- |
| `normal_2.sh` | 정상 모니터링 | 2초 간격으로 pods `list` 30회 | 같은 사용자, 단일 리소스 주기 반복, `code=200` |
| `abnormal_4.sh` | 권한 탐색 | `kubectl auth can-i` 3회 (selfsubjectrulesreviews, selfsubjectaccessreviews `create`) | 같은 사용자, `code=201`, 403 없음 |
| `abnormal_5.sh` | 저속 resource enumeration | pods/services/configmaps를 15초 간격으로 6회 조회 | 같은 사용자, `code=200`, 10초당 최대 3건 |
| `abnormal_6.sh` | 허용 리소스 enumeration | pods/services/configmaps를 연속 6회 조회 | 같은 사용자, `code=200`, 빈도 급증 |

### 실행

프로젝트 루트에서 실행합니다. 시나리오는 한 번에 하나씩 실행합니다. 동시에 실행하면 로그 구간이 섞입니다.

```bash
# 시나리오 실행과 로그 수집 (약 3분)
./category3/detector/collect.sh all

# 탐지와 평가
python3 category3/detector/detect.py category3/results/raw/*.jsonl \
  --json category3/results/summary.json > category3/results/report.md
```

`collect.sh`는 시나리오 실행 전후의 audit.log 줄 수를 기록합니다. 그 사이 구간을 `results/raw/<시나리오>.jsonl`에 저장합니다. 파일명 접두어가 정답 라벨입니다(`normal*` 정상, `abnormal*` 공격). 시나리오 하나만 수집하려면 `./category3/detector/collect.sh abnormal_4`를 실행합니다.

추가 시나리오도 개별 실행할 수 있습니다.

```bash
./category3/normal_2.sh
./category3/abnormal_4.sh
./category3/abnormal_5.sh
./category3/abnormal_6.sh
```

예시 이벤트는 `logs/normal_2.log`, `logs/abnormal_4.log`~`abnormal_6.log`에 있습니다. 수집 로그에서 대상 ServiceAccount의 `ResponseComplete` 이벤트만 남긴 것입니다.

### 탐지 방법

전처리는 3단계입니다.

1. `user.username`이 `system:serviceaccount:pbl-security:pbl-crypto-platform-app`인 이벤트만 남깁니다. 이름 문자열로 검색하면 관리자가 이 ServiceAccount를 대상으로 보낸 요청(`create token` 등)도 포함됩니다.
2. `stage`가 `ResponseComplete`인 이벤트만 남깁니다. Audit Policy의 두 번째 규칙에는 `omitStages`가 없습니다. 그래서 pods, services, secrets 요청은 `RequestReceived` 단계에서 한 번 더 기록됩니다.
3. `objectRef`가 없는 discovery 요청을 제외합니다.

판정 단위는 세션(로그 파일, 토큰 JTI)입니다. 스크립트는 실행할 때마다 새 토큰을 발급합니다. 그래서 스크립트 1회 실행이 세션 1개입니다. 켜진 규칙 중 하나라도 일치하면 공격으로 판정합니다.

| ID | 관찰 속성 | 조건 | 심각도 |
| --- | --- | --- | --- |
| D1 | 대상 | `resource = secrets` (결과 무관) | High |
| D2 | 대상 | `subresource`가 `exec`, `attach`, `portforward` 중 하나 | High |
| D3 | 인가 결과 | `decision = forbid` 또는 `code = 403` | Medium |
| D4 | 빈도 | 10초 창에서 같은 (verb, resource) 3회 이상, 또는 전체 10회 이상 | Medium |
| D5 | 호출 도구 | `userAgent`가 `kubectl/`로 시작하지 않음 | Low |
| D6 | 권한 탐색 | `resource`가 `selfsubjectrulesreviews` 또는 `selfsubjectaccessreviews` | Medium |
| D4' | 빈도 (개선안) | 10초 창에서 같은 (verb, resource) 3회 이상이고 리소스 종류 2개 이상, 또는 전체 10회 이상 | Medium |

### 결과

kind v1.31 클러스터에서 8개 시나리오를 1회씩 실행했습니다(세션 8개: 정상 2, 공격 6).

| 세트 | 구성 | TP | FP | FN | TN | Precision | Recall |
| --- | --- | :-: | :-: | :-: | :-: | :-: | :-: |
| A | D3 | 3 | 0 | 3 | 2 | 1.00 | 0.50 |
| B | D1~D5 | 4 | 1 | 2 | 1 | 0.80 | 0.67 |
| C | D1~D6 | 5 | 1 | 1 | 1 | 0.83 | 0.83 |
| D | D1~D6에서 D4 제외 | 4 | 0 | 2 | 2 | 1.00 | 0.67 |
| E | D1~D6에서 D4를 D4'로 교체 | 5 | 0 | 1 | 2 | 1.00 | 0.83 |

| 시나리오 | 세트 C 일치 규칙 | 판정 |
| --- | --- | :-: |
| `normal.sh` | 없음 | TN |
| `normal_2.sh` | D4 (10초 창 반복 5회) | FP |
| `abnormal_1.sh` | D1, D3 | TP |
| `abnormal_2.sh` | D2, D3, D5 | TP |
| `abnormal_3.sh` | D1, D3, D4 | TP |
| `abnormal_4.sh` | D6 | TP |
| `abnormal_5.sh` | 없음 (10초 창 최대 3건) | FN |
| `abnormal_6.sh` | D4 | TP |

전처리 건수, D4 임계값 실험, 경보별 근거 이벤트(auditID)는 `results/report.md`에 있습니다.

### 오탐·미탐 분석과 한계

- 전처리: 수집 구간의 이벤트는 838건입니다. 이 중 ServiceAccount 이름을 포함한 이벤트는 196건입니다. 그중 행위자가 이 ServiceAccount인 이벤트는 170건입니다. 나머지 26건은 관리자의 `get serviceaccounts`, `create token` 등입니다. 중복 기록은 `RequestReceived` 72건(pods 52, services 13, secrets 7)과 `pods/exec`의 `ResponseStarted` 1건입니다.
- 오탐(`normal_2.sh`): 2초 간격으로 조회하면 10초 창에 같은 요청이 5회 들어옵니다. 그래서 D4와 일치합니다. 반복 임계값을 6 이상으로 하면 오탐이 없어집니다. 그러나 이 값은 시험 시나리오를 보고 정한 값입니다. D4를 끄면(세트 D) 오탐은 없어지지만 `abnormal_6.sh`를 탐지하지 못합니다.
- 미탐(`abnormal_5.sh`): 10초 창에 최대 3건만 들어옵니다. 그래서 어떤 규칙과도 일치하지 않습니다. 세 빈도 지표마다 값이 더 큰 정상 세션이 있습니다. 10초 창 반복은 1회(`normal.sh` 2회), 10초 창 요청 수는 3건(`normal.sh` 5건), 세션 요청 수는 18건(`normal_2.sh` 30건)입니다. 그래서 어떤 빈도 임계값으로 탐지해도 정상 세션이 함께 탐지됩니다. 예를 들어 세트 E에 세션 요청 수 18건 이상 조건을 추가하면, 미탐 1건이 `normal_2.sh`의 오탐 1건으로 바뀝니다.
- 한계:
  - 규칙과 시나리오를 같은 사람이 설계했습니다. D4'는 결과를 본 뒤 정의했습니다.
  - 데이터는 ServiceAccount 1개, 세션 8개입니다.
  - D5의 기준(`kubectl/`)은 실습 환경의 가정입니다.
  - Metadata 수준에서는 응답 본문(예: access review의 `allowed`)이 기록되지 않습니다.
  - 실제 Pod 토큰은 주기적으로 갱신됩니다. 그래서 공격 하나가 여러 세션으로 나뉠 수 있습니다.

### 산출물

| 경로 | 내용 |
| --- | --- |
| `normal_2.sh`, `abnormal_4.sh`~`abnormal_6.sh` | 추가 시나리오 |
| `detector/collect.sh` | 시나리오 실행과 Audit Log 구간 수집 |
| `detector/detect.py` | 전처리, 세션 분할, 규칙 판정, 평가 (Python 표준 라이브러리) |
| `logs/normal_2.log`, `logs/abnormal_4.log`~`abnormal_6.log` | 추가 시나리오의 예시 이벤트 |
| `results/raw/` | 수집 로그 8개 |
| `results/report.md`, `results/summary.json` | 탐지 결과 보고서와 요약 |
