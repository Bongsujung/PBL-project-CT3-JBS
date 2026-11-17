# Category 3 탐지 결과

- 생성: 2026-11-17 18:42:17
- 입력 파일: 8개
- 대상: `system:serviceaccount:pbl-security:pbl-crypto-platform-app`
- D4: 10초 창, 같은 (verb, resource) ≥ 3회 또는 전체 ≥ 10건

## 1. 전처리

| 단계 | 건수 |
|---|---:|
| 수집 구간 전체 | 838 |
| SA 이름 포함 | 196 |
| (1) user.username 일치 | 170 |
| (2) 제거: ResponseComplete 아님 | 73 |
| (3) 제거: objectRef 없음 | 2 |
| **탐지 입력** | **95** |

SA 이름을 포함하지만 행위자가 다른 이벤트: 26건

| user | verb | resource | 건수 |
|---|---|---|---:|
| `kubernetes-admin` | get | serviceaccounts | 16 |
| `kubernetes-admin` | create | serviceaccounts/token | 8 |
| `kubernetes-admin` | create | serviceaccounts | 1 |
| `kubernetes-admin` | create | rolebindings | 1 |

(2)에서 제거한 이벤트:

| stage | resource | 건수 |
|---|---|---:|
| RequestReceived | pods | 52 |
| RequestReceived | services | 13 |
| RequestReceived | secrets | 7 |
| ResponseStarted | pods/exec | 1 |

## 2. 세션 판정 (세트 C: D1, D2, D3, D4, D5, D6)

세션 = (파일, 토큰 JTI). 반복과 전체는 10초 창 최대값.

| 시나리오 | 라벨 | JTI | 요청 | 지속(s) | 반복 | 전체 | D1 | D2 | D3 | D4 | D5 | D6 | 판정 | 심각도 | 결과 |
|---|---|---|---:|---:|---:|---:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|:-:|
| normal | 정상 | `e7916877` | 5 | 0.1 | 2 | 5 |  |  |  |  |  |  | 정상 | - | **TN** |
| normal_2 | 정상 | `ff20e208` | 30 | 58.9 | 5 | 5 |  |  |  | ● |  |  | 공격 | Medium | **FP** |
| abnormal_1 | 공격 | `6db720cc` | 1 | 0.0 | 1 | 1 | ● |  | ● |  |  |  | 공격 | High | **TP** |
| abnormal_2 | 공격 | `8eff3e6c` | 2 | 0.0 | 1 | 2 |  | ● | ● |  | ● |  | 공격 | High | **TP** |
| abnormal_3 | 공격 | `98d40459` | 18 | 0.5 | 6 | 18 | ● |  | ● | ● |  |  | 공격 | High | **TP** |
| abnormal_4 | 공격 | `a281f6f5` | 3 | 0.1 | 2 | 3 |  |  |  |  |  | ● | 공격 | Medium | **TP** |
| abnormal_5 | 공격 | `e8cdbf41` | 18 | 75.5 | 1 | 3 |  |  |  |  |  |  | 정상 | - | **FN** |
| abnormal_6 | 공격 | `58bf6f77` | 18 | 0.5 | 6 | 18 |  |  |  | ● |  |  | 공격 | Medium | **TP** |

## 3. 규칙별 경보

| 규칙 | 이름 | 심각도 | 경보 세션 (정상/공격) | 근거 이벤트 |
|---|---|---|---|---:|
| D1 | 민감 리소스 접근 | High | 0 / 2 | 7 |
| D2 | 원격 실행 시도 | High | 0 / 1 | 1 |
| D3 | 인가 거부 | Medium | 0 / 3 | 8 |
| D4 | 반복 열거 | Medium | 1 / 2 | 52 |
| D5 | 호출 도구 이탈 | Low | 0 / 1 | 1 |
| D6 | 권한 탐색 | Medium | 0 / 1 | 3 |
| D4' | 반복 열거 (개선안) | Medium | 0 / 2 | 24 |

## 4. 규칙 세트 비교

세션: 정상 2, 공격 6

| 세트 | 규칙 | 설명 | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| A | D3 | D3만 사용 | 3 | 0 | 3 | 2 | 1.00 | 0.50 | 0.67 |
| B | D1, D2, D3, D4, D5 | D6 없음 | 4 | 1 | 2 | 1 | 0.80 | 0.67 | 0.73 |
| C | D1, D2, D3, D4, D5, D6 | 제안 구성 | 5 | 1 | 1 | 1 | 0.83 | 0.83 | 0.83 |
| D | D1, D2, D3, D5, D6 | C에서 D4 제외 | 4 | 0 | 2 | 2 | 1.00 | 0.67 | 0.80 |
| E | D1, D2, D3, D4', D5, D6 | C에서 D4를 D4'로 교체 | 5 | 0 | 1 | 2 | 1.00 | 0.83 | 0.91 |

시나리오별 결과:

| 시나리오 | 라벨 | A | B | C | D | E |
|---|---|:-:|:-:|:-:|:-:|:-:|
| normal | 정상 | TN | TN | TN | TN | TN |
| normal_2 | 정상 | TN | FP | FP | TN | TN |
| abnormal_1 | 공격 | TP | TP | TP | TP | TP |
| abnormal_2 | 공격 | TP | TP | TP | TP | TP |
| abnormal_3 | 공격 | TP | TP | TP | TP | TP |
| abnormal_4 | 공격 | FN | FN | TP | TP | TP |
| abnormal_5 | 공격 | FN | FN | FN | FN | FN |
| abnormal_6 | 공격 | FN | TP | TP | FN | TP |

## 5. D4 임계값

| 시나리오 | 10초 창 최대 반복 | 10초 창 최대 요청 | 10초 창 리소스 종류 | 세션 요청 |
|---|---:|---:|---:|---:|
| normal | 2 | 5 | 3 | 5 |
| normal_2 | 5 | 5 | 1 | 30 |
| abnormal_1 | 1 | 1 | 1 | 1 |
| abnormal_2 | 1 | 2 | 2 | 2 |
| abnormal_3 | 6 | 18 | 3 | 18 |
| abnormal_4 | 2 | 3 | 2 | 3 |
| abnormal_5 | 1 | 3 | 3 | 18 |
| abnormal_6 | 6 | 18 | 3 | 18 |

반복 임계값 변경 (세트 C, 전체 임계값 10):

| 반복 임계값 | TP | FP | FN | TN | Precision | Recall |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 2 | 5 | 2 | 1 | 0 | 0.71 | 0.83 |
| 3 (설계값) | 5 | 1 | 1 | 1 | 0.83 | 0.83 |
| 4 | 5 | 1 | 1 | 1 | 0.83 | 0.83 |
| 5 | 5 | 1 | 1 | 1 | 0.83 | 0.83 |
| 6 | 5 | 0 | 1 | 2 | 1.00 | 0.83 |
| 7 | 5 | 0 | 1 | 2 | 1.00 | 0.83 |
| 8 | 5 | 0 | 1 | 2 | 1.00 | 0.83 |

## 6. 근거 이벤트 (규칙당 최대 3건)

### normal (`e7916877`): TN (일치 규칙 없음)

요청 5건, 10초 창 최대 반복 2, 최대 요청 5.

### normal_2 (`ff20e208`): FP (D4)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D4 | `c32820f2` | 12:09:37.444 | list | pods | 200 | allow | kubectl/v1.37.2 |
| D4 | `cef91308` | 12:09:39.474 | list | pods | 200 | allow | kubectl/v1.37.2 |
| D4 | `b5e08463` | 12:09:41.510 | list | pods | 200 | allow | kubectl/v1.37.2 |

### abnormal_1 (`6db720cc`): TP (D1, D3)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D1 | `18a3d4aa` | 12:10:36.562 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D3 | `18a3d4aa` | 12:10:36.562 | list | secrets | 403 | forbid | kubectl/v1.37.2 |

### abnormal_2 (`8eff3e6c`): TP (D2, D3, D5)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D2 | `64c27ae4` | 12:10:38.847 | create | pods/exec | 403 | forbid | curl/7.81.0 |
| D3 | `64c27ae4` | 12:10:38.847 | create | pods/exec | 403 | forbid | curl/7.81.0 |
| D5 | `64c27ae4` | 12:10:38.847 | create | pods/exec | 403 | forbid | curl/7.81.0 |

### abnormal_3 (`98d40459`): TP (D1, D3, D4)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D1 | `cc590a22` | 12:10:41.119 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D1 | `25bfdf97` | 12:10:41.210 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D1 | `134d86c5` | 12:10:41.298 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D3 | `cc590a22` | 12:10:41.119 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D3 | `25bfdf97` | 12:10:41.210 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D3 | `134d86c5` | 12:10:41.298 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D4 | `c14b882a` | 12:10:41.266 | list | pods | 200 | allow | kubectl/v1.37.2 |
| D4 | `134d86c5` | 12:10:41.298 | list | secrets | 403 | forbid | kubectl/v1.37.2 |
| D4 | `7fb33d78` | 12:10:41.324 | list | configmaps | 200 | allow | kubectl/v1.37.2 |

### abnormal_4 (`a281f6f5`): TP (D6)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D6 | `c80d5200` | 12:10:43.842 | create | selfsubjectrulesreviews | 201 | allow | kubectl/v1.37.2 |
| D6 | `7750a7c6` | 12:10:43.869 | create | selfsubjectaccessreviews | 201 | allow | kubectl/v1.37.2 |
| D6 | `1b8029d7` | 12:10:43.896 | create | selfsubjectaccessreviews | 201 | allow | kubectl/v1.37.2 |

### abnormal_5 (`e8cdbf41`): FN (일치 규칙 없음)

요청 18건, 10초 창 최대 반복 1, 최대 요청 3.

### abnormal_6 (`58bf6f77`): TP (D4)

| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |
|---|---|---|---|---|---|---|---|
| D4 | `d6a41df8` | 12:12:04.113 | list | pods | 200 | allow | kubectl/v1.37.2 |
| D4 | `f66d87b1` | 12:12:04.141 | list | services | 200 | allow | kubectl/v1.37.2 |
| D4 | `c0eaac00` | 12:12:04.167 | list | configmaps | 200 | allow | kubectl/v1.37.2 |

