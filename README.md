# cvss4

[![npm version](https://img.shields.io/npm/v/cvss4.svg)](https://www.npmjs.com/package/cvss4)
[![npm downloads](https://img.shields.io/npm/dm/cvss4.svg)](https://www.npmjs.com/package/cvss4)
[![license](https://img.shields.io/npm/l/cvss4.svg)](LICENSE)

CVSS score calculator for JavaScript and TypeScript. Supports **CVSS 3.0, 3.1 and 4.0** through one function.

Pass in any CVSS vector string and get the score back. You don't have to check the version first, so when your scanner or vendor moves from v3.1 to v4.0, your code stays the same.

```javascript
import { calculateBaseScore } from 'cvss4';

calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');               // 9.8
calculateBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'); // 9.3
```

- Zero runtime dependencies (only `tslib`)
- TypeScript types included
- Works in Node.js (CommonJS and ES modules) and the browser (UMD)
- Scores are checked against FIRST's official calculators

---

## Install

```bash
npm install cvss4
```

---

## What's supported

| Version | Base | Temporal | Environmental | Threat |
| ------- | :--: | :------: | :-----------: | :----: |
| CVSS 3.0 | ✅ | ✅ | ✅ | n/a |
| CVSS 3.1 | ✅ | ✅ | ✅ | n/a |
| CVSS 4.0 | ✅ | n/a | ✅ | ✅ |

CVSS 4.0 gives one score for the whole vector. `calculateBaseScore` applies any threat (`E`) and environmental (`CR`, `MAV`, ...) metrics in the vector, the same way FIRST's v4.0 calculator does. Supplemental metrics (`S`, `AU`, `R`, `V`, `RE`, `U`) are accepted but don't change the score, as the spec says:

```javascript
calculateBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U'); // 8.1
```

CVSS 2.0 is not supported.

---

## Usage

### Score any vector

```javascript
import { calculateBaseScore, humanizeScore } from 'cvss4';

const score = calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H'); // 9.9
humanizeScore(score); // 'Critical'
```

### Temporal and environmental scores (CVSS 3.x)

```javascript
import { calculateTemporalScore, calculateEnvironmentalScore } from 'cvss4';

calculateTemporalScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C');         // 8.8
calculateEnvironmentalScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:L/AR:L/MAV:A'); // 8.8
```

Metrics you leave out use their default (`X`) value.

### Impact and exploitability sub-scores (CVSS 3.x)

```javascript
import { calculateBaseResult } from 'cvss4';

const { score, impact, exploitability } = calculateBaseResult('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
// score: 9.8, impact: 5.9, exploitability: 3.9
```

`calculateTemporalResult` and `calculateEnvironmentalResult` return the same shape.

### Invalid vectors

The calculate functions throw an `Error` if the vector is malformed, is missing a required metric, or uses an unsupported version:

```javascript
try {
  calculateBaseScore('CVSS:3.1/AV:N');
} catch (err) {
  console.error(err.message); // Missing mandatory CVSS metric ...
}
```

### CommonJS

```javascript
const { calculateBaseScore } = require('cvss4');
```

### Browser

```html
<script src="https://unpkg.com/cvss4/dist/bundle.umd.js"></script>
<script>
  console.log(cvss.calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
</script>
```

---

## API

### Scores

| Function | Versions | Returns |
| -------- | -------- | ------- |
| `calculateBaseScore(vector)` | 3.0, 3.1, 4.0 | Score as a number (for 4.0, the full CVSS-B/BT/BE/BTE score) |
| `calculateTemporalScore(vector)` | 3.0, 3.1 | Temporal score |
| `calculateEnvironmentalScore(vector)` | 3.0, 3.1 | Environmental score |
| `calculateBaseResult(vector)` | 3.0, 3.1 | `{ score, impact, exploitability, metricsMap }` |
| `calculateTemporalResult(vector)` | 3.0, 3.1 | `{ score, impact, exploitability, metricsMap }` |
| `calculateEnvironmentalResult(vector)` | 3.0, 3.1 | `{ score, impact, exploitability, metricsMap }` |
| `calculateBaseScoreV4(vector)` | 4.0 | Score (same as `calculateBaseScore` for 4.0 vectors) |

### Severity

| Function | Returns |
| -------- | ------- |
| `humanizeScore(score)` | `'None'`, `'Low'`, `'Medium'`, `'High'` or `'Critical'` |
| `calculateQualScore(score)` | Same ratings (alias kept for v4 code) |

### Validation and parsing

| Function | Versions | What it does |
| -------- | -------- | ------------ |
| `validate(vector)` | 3.0, 3.1 | Throws if the vector is invalid, otherwise returns `{ metricsMap, versionStr, isTemporal, isEnvironmental }` |
| `validateVectorV4(vector)` | 4.0 | Returns `{ valid, error? }` without throwing |
| `parseVersion(vector)` | all | `'3.0'`, `'3.1'` or `'4.0'` |
| `parseVector(vector)` | all | The vector without the `CVSS:x.x/` prefix |
| `parseMetricsAsMap(vector)` | all | Metrics as a `Map` |

### Labels (CVSS 3.x)

```javascript
humanizeBaseMetric('AV');             // 'Attack Vector'
humanizeBaseMetricValue('N', 'AV');   // 'Network'
```

Lower-level helpers (`calculateIss`, `calculateImpact`, `calculateExploitability`, `macroVector`, ...) are also exported if you need them.

---

## Accuracy

Scores are compared against FIRST's reference calculators ([v3.0](https://www.first.org/cvss/calculator/3.0), [v3.1](https://www.first.org/cvss/calculator/3.1), [v4.0](https://www.first.org/cvss/calculator/4.0)) on large sets of random vectors, including temporal and environmental metrics.

Two things that can look like bugs but follow the spec:

- **CVSS 3.1 environmental can be higher than base, even with no environmental metrics.** In 3.1, the environmental formula for changed scope uses `(MISS × 0.9731 − 0.02)^13` instead of `(ISS − 0.02)^15`. For example, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` scores 9.9 base and 10.0 environmental. FIRST's calculator gives the same result.
- **CVSS 3.0 rounding.** FIRST's v3.0 calculator sometimes rounds up one step too far because of floating point (for example 5.0 × 0.92 = 4.6000000000000005 → 4.7). This library returns the mathematically correct 4.6. CVSS 3.1 fixed this in the spec, so 3.1 scores match exactly.

---

## Development

```bash
npm install
npm test
npm run build
```

Bug reports and pull requests are welcome. If a score looks wrong, please include the vector and the score FIRST's calculator gives for it.

---

## License

MIT. See [LICENSE](LICENSE).

Thanks to [NeuraLegion](https://github.com/NeuraLegion) for the original version of this library.
