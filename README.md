
# CVSS

The **Common Vulnerability Scoring System (CVSS)** is a [scoring framework](https://www.first.org/cvss/) that provides numerical scores to assess the severity of software vulnerabilities. This TypeScript-based library offers support for CVSS versions **3.0**, **3.1**, and **4.0** for calculating and validating Base Scores.

---

## Basics

CVSS produces numerical scores based on principal vulnerability characteristics to determine the severity of a vulnerability. These scores help compare the relative risks of different vulnerabilities.

A CVSS vector string consists of:

1. A version identifier starting with `CVSS:`.
2. A set of `/`-separated metrics. Each metric is represented as a key-value pair (`metric:value`).

### Example Vector String

**Sample CVSS v3.1 vector string**:  
`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N`

**Base Score**: [3.8](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N)  
**Severity**: [Low](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N)

---

## Features

1. **Supported CVSS Versions**:  
   - [CVSS 3.0](https://www.first.org/cvss/v3-0/)  
   - [CVSS 3.1](https://www.first.org/cvss/v3-1/)  
   - [CVSS 4.0](https://www.first.org/cvss/v4-0/)  

2. **Metric Group Coverage**:  
   Currently supports **Base Metrics**. Future updates may include **Temporal** and **Environmental Metrics**.

---

## Installation

Install the library using npm:

```bash
npm install --save cvss4
```

---

## API Reference

### **Score Calculation**

- `calculateBaseScore(cvssString): number`  
  Computes the Base Score of a CVSS vector string.  
  Example:  
  ```javascript
  import { calculateBaseScore } from 'cvss4';
  console.log(calculateBaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
  ```

- `calculateIss(metricsMap): number`  
  Calculates the [Impact Sub-Score (ISS)](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations).

- `calculateImpact(metricsMap, iss): number`  
  Computes the [Impact](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations).

- `calculateExploitability(metricsMap): number`  
  Computes the [Exploitability](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations).

---

### **Validation**

- `validate(cvssString): void`  
  Validates the CVSS vector string. Throws an error if the string is invalid or unsupported.  
  Example:  
  ```javascript
  import { validate } from 'cvss4';
  validate('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N');
  ```

---

### **Humanization**

- `humanizeBaseMetric(metric: string): string`  
  Converts an abbreviated metric name to its full form.  
  Example:  
  ```javascript
  humanizeBaseMetric('C'); // Returns: 'Confidentiality'
  ```

- `humanizeBaseMetricValue(value: string, metric: string): string`  
  Converts an abbreviated metric value to its full form.  
  Example:  
  ```javascript
  humanizeBaseMetricValue('N', 'AV'); // Returns: 'Network'
  ```

---

## Usage Examples

### **Node.js (CommonJS)**

```javascript
const cvss = require('cvss4');
console.log(cvss.calculateBaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
```

### **Node.js (ES Modules)**

```javascript
import { calculateBaseScore } from 'cvss4';
console.log(calculateBaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
```

### **Browser (UMD)**

```html
<script src="./node_modules/cvss4/dist/bundle.umd.js"></script>
<script>
  alert(cvss.calculateBaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
</script>
```

---

## Development

Contributions are welcome. Please ensure your code passes linting (`npm run lint`) and tests (`npm test`) before submitting a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE file](LICENSE) for details.

Special thanks to [NeuraLegion](https://github.com/NeuraLegion) for the initial version of this library.
