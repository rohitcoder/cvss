import {
  BaseMetric,
  BaseMetricValue,
  EnvironmentalMetric,
  EnvironmentalMetricValue,
  MaxSeverityData,
  Metric,
  MetricValue,
  TemporalMetric,
  TemporalMetricValue,
  cvssLookup_globalV4,
  environmentalMetrics,
  expectedMetricOrder,
  maxComposed,
  maxSeverityV4,
  temporalMetrics
} from './models';
import { validate } from './validator';

const detectCvssVersion = (cvssString: string) => {
  const versionPrefix = cvssString.split('/')[0];
  if (versionPrefix.startsWith('CVSS:4.0')) return '4.0';
  if (versionPrefix.startsWith('CVSS:3.')) return '3.1';
  throw new Error(`Unsupported CVSS version: ${versionPrefix}`);
};

// https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
const baseMetricValueScores: Record<
  BaseMetric,
  Partial<Record<BaseMetricValue, number>> | null
> = {
  [BaseMetric.ATTACK_VECTOR]: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  [BaseMetric.ATTACK_COMPLEXITY]: { L: 0.77, H: 0.44 },
  [BaseMetric.PRIVILEGES_REQUIRED]: null, // scope-dependent: see getPrivilegesRequiredNumericValue()
  [BaseMetric.USER_INTERACTION]: { N: 0.85, R: 0.62 },
  [BaseMetric.SCOPE]: { U: 0, C: 0 },
  [BaseMetric.CONFIDENTIALITY]: { N: 0, L: 0.22, H: 0.56 },
  [BaseMetric.INTEGRITY]: { N: 0, L: 0.22, H: 0.56 },
  [BaseMetric.AVAILABILITY]: { N: 0, L: 0.22, H: 0.56 }
};

const temporalMetricValueScores: Record<
  TemporalMetric,
  Partial<Record<TemporalMetricValue, number>> | null
> = {
  [TemporalMetric.EXPLOIT_CODE_MATURITY]: {
    X: 1,
    U: 0.91,
    F: 0.97,
    P: 0.94,
    H: 1
  },
  [TemporalMetric.REMEDIATION_LEVEL]: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
  [TemporalMetric.REPORT_CONFIDENCE]: { X: 1, U: 0.92, R: 0.96, C: 1 }
};

const environmentalMetricValueScores: Record<
  EnvironmentalMetric,
  Partial<Record<EnvironmentalMetricValue, number>> | null
> = {
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: {
    M: 1,
    L: 0.5,
    H: 1.5,
    X: 1
  },
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: { M: 1, L: 0.5, H: 1.5, X: 1 },
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: {
    M: 1,
    L: 0.5,
    H: 1.5,
    X: 1
  },
  [EnvironmentalMetric.MODIFIED_ATTACK_VECTOR]:
    baseMetricValueScores[BaseMetric.ATTACK_VECTOR],
  [EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY]:
    baseMetricValueScores[BaseMetric.ATTACK_COMPLEXITY],
  [EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED]: null, // scope-dependent: see getPrivilegesRequiredNumericValue()
  [EnvironmentalMetric.MODIFIED_USER_INTERACTION]:
    baseMetricValueScores[BaseMetric.USER_INTERACTION],
  [EnvironmentalMetric.MODIFIED_SCOPE]: baseMetricValueScores[BaseMetric.SCOPE],
  [EnvironmentalMetric.MODIFIED_CONFIDENTIALITY]:
    baseMetricValueScores[BaseMetric.CONFIDENTIALITY],
  [EnvironmentalMetric.MODIFIED_INTEGRITY]:
    baseMetricValueScores[BaseMetric.INTEGRITY],
  [EnvironmentalMetric.MODIFIED_AVAILABILITY]:
    baseMetricValueScores[BaseMetric.AVAILABILITY]
};

const getPrivilegesRequiredNumericValue = (
  value: MetricValue,
  scopeValue: MetricValue
): number => {
  if (scopeValue !== 'U' && scopeValue !== 'C' && scopeValue !== 'X') {
    throw new Error(`Unknown Scope value: ${scopeValue}`);
  }

  switch (value) {
    case 'N':
      return 0.85;
    case 'L':
      return scopeValue === 'U' ? 0.62 : 0.68;
    case 'H':
      return scopeValue === 'U' ? 0.27 : 0.5;
    default:
      throw new Error(`Unknown PrivilegesRequired value: ${value}`);
  }
};

const getMetricValue = (
  metric: Metric,
  metricsMap: Map<Metric, MetricValue>
): MetricValue => {
  if (!metricsMap.has(metric)) {
    console.log("metricsMap", metricsMap);
    throw new Error(`Missing metric: ${metric}`);
  }

  return metricsMap.get(metric) as BaseMetricValue;
};

const getMetricNumericValue = (
  metric: Metric,
  metricsMap: Map<Metric, MetricValue>
): number => {
  const value = getMetricValue(
    (metric as BaseMetric) || TemporalMetric || EnvironmentalMetric,
    metricsMap
  );

  if (metric === BaseMetric.PRIVILEGES_REQUIRED) {
    return getPrivilegesRequiredNumericValue(
      value,
      getMetricValue(BaseMetric.SCOPE as BaseMetric, metricsMap)
    );
  }
  if (metric === EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED) {
    return getPrivilegesRequiredNumericValue(
      value,
      getMetricValue(
        EnvironmentalMetric.MODIFIED_SCOPE as EnvironmentalMetric,
        metricsMap
      )
    );
  }

  const score: Partial<Record<MetricValue, number>> | null = {
    ...baseMetricValueScores,
    ...temporalMetricValueScores,
    ...environmentalMetricValueScores
  }[metric];

  if (!score) {
    throw new Error(`Internal error. Missing metric score: ${metric}`);
  }

  return score[value]!;
};

// ISS = 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
export const calculateIss = (metricsMap: Map<Metric, MetricValue>): number => {
  const confidentiality = getMetricNumericValue(
    BaseMetric.CONFIDENTIALITY,
    metricsMap
  );
  const integrity = getMetricNumericValue(BaseMetric.INTEGRITY, metricsMap);
  const availability = getMetricNumericValue(
    BaseMetric.AVAILABILITY,
    metricsMap
  );

  return 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
};

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// MISS = Minimum ( 1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement × ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ], 0.915)
export const calculateMiss = (metricsMap: Map<Metric, MetricValue>): number => {
  const rConfidentiality = getMetricNumericValue(
    EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
    metricsMap
  );
  const mConfidentiality = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_CONFIDENTIALITY,
    metricsMap
  );

  const rIntegrity = getMetricNumericValue(
    EnvironmentalMetric.INTEGRITY_REQUIREMENT,
    metricsMap
  );
  const mIntegrity = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_INTEGRITY,
    metricsMap
  );

  const rAvailability = getMetricNumericValue(
    EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
    metricsMap
  );
  const mAvailability = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_AVAILABILITY,
    metricsMap
  );

  return Math.min(
    1 -
    (1 - rConfidentiality * mConfidentiality) *
    (1 - rIntegrity * mIntegrity) *
    (1 - rAvailability * mAvailability),
    0.915
  );
};

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Impact =
//   If Scope is Unchanged 	6.42 × ISS
//   If Scope is Changed 	7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
export const calculateImpact = (
  metricsMap: Map<Metric, MetricValue>,
  iss: number
): number =>
  metricsMap.get(BaseMetric.SCOPE) === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// ModifiedImpact =
// If ModifiedScope is Unchanged	6.42 × MISS
// If ModifiedScope is Changed	7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
// ModifiedExploitability =	8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
// Note : Math.pow is 15 in 3.0 but 13 in 3.1
export const calculateModifiedImpact = (
  metricsMap: Map<Metric, MetricValue>,
  miss: number,
  versionStr: string | null
): number =>
  metricsMap.get(EnvironmentalMetric.MODIFIED_SCOPE) === 'U'
    ? 6.42 * miss
    : 7.52 * (miss - 0.029) -
    3.25 *
    Math.pow(
      miss * (versionStr === '3.0' ? 1 : 0.9731) - 0.02,
      versionStr === '3.0' ? 15 : 13
    );

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
export const calculateExploitability = (
  metricsMap: Map<Metric, MetricValue>
): number =>
  8.22 *
  getMetricNumericValue(BaseMetric.ATTACK_VECTOR, metricsMap) *
  getMetricNumericValue(BaseMetric.ATTACK_COMPLEXITY, metricsMap) *
  getMetricNumericValue(BaseMetric.PRIVILEGES_REQUIRED, metricsMap) *
  getMetricNumericValue(BaseMetric.USER_INTERACTION, metricsMap);

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// Exploitability = 8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
export const calculateModifiedExploitability = (
  metricsMap: Map<Metric, MetricValue>
): number =>
  8.22 *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_ATTACK_VECTOR,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_USER_INTERACTION,
    metricsMap
  );

// https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
const roundUp = (input: number): number => {
  const intInput = Math.round(input * 100000);

  return intInput % 10000 === 0
    ? intInput / 100000
    : (Math.floor(intInput / 10000) + 1) / 10;
};

export const modifiedMetricsMap: { [key: string]: BaseMetric } = {
  MAV: BaseMetric.ATTACK_VECTOR,
  MAC: BaseMetric.ATTACK_COMPLEXITY,
  MPR: BaseMetric.PRIVILEGES_REQUIRED,
  MUI: BaseMetric.USER_INTERACTION,
  MS: BaseMetric.SCOPE,
  MC: BaseMetric.CONFIDENTIALITY,
  MI: BaseMetric.INTEGRITY,
  MA: BaseMetric.AVAILABILITY
};

// When Modified Temporal metric value is 'Not Defined' ('X'), which is the default value,
// then Base metric value should be used.
export const populateTemporalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...temporalMetrics].forEach((metric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'X');
    }
  });

  return metricsMap;
};

export const populateEnvironmentalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...environmentalMetrics].forEach((metric: EnvironmentalMetric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'X');
    }

    if (metricsMap.get(metric) === 'X') {
      metricsMap.set(
        metric,
        metricsMap.has(modifiedMetricsMap[metric])
          ? (metricsMap.get(modifiedMetricsMap[metric]) as MetricValue)
          : 'X'
      );
    }
  });

  return metricsMap;
};

export type ScoreResult = {
  score: number;
  impact: number;
  exploitability: number;
  metricsMap: Map<Metric, MetricValue>;
};

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// If Impact <= 0 => 0; else
// If Scope is Unchanged => Roundup (Minimum [(Impact + Exploitability), 10])
// If Scope is Changed => Roundup (Minimum [1.08 × (Impact + Exploitability), 10])
export const calculateBaseResult = (cvssString: string): ScoreResult => {
  const { metricsMap } = validate(cvssString);

  const iss = calculateIss(metricsMap);
  const impact = calculateImpact(metricsMap, iss);
  const exploitability = calculateExploitability(metricsMap);
  const scopeUnchanged = metricsMap.get(BaseMetric.SCOPE) === 'U';

  const score =
    impact <= 0
      ? 0
      : scopeUnchanged
        ? roundUp(Math.min(impact + exploitability, 10))
        : roundUp(Math.min(1.08 * (impact + exploitability), 10));

  return {
    score,
    metricsMap,
    impact: impact <= 0 ? 0 : roundUp(impact),
    exploitability: impact <= 0 ? 0 : roundUp(exploitability)
  };
};

export const calculateBaseScore = (cvssString: string): number => {
  const version = detectCvssVersion(cvssString);
  if (version === '4.0') {
    return calculateBaseScoreV4(cvssString);
  } else if (version === '3.1') {
    const { score } = calculateBaseResult(cvssString);
    return score;
  } else {
    throw new Error(`Unsupported CVSS version: ${version}`);
  }
};

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// If ModifiedImpact <= 0 =>	0; else
// If ModifiedScope is Unchanged =>	Roundup (Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10)] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
// If ModifiedScope is Changed =>	Roundup (Roundup [Minimum (1.08 × [ModifiedImpact + ModifiedExploitability], 10)] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
export const calculateEnvironmentalResult = (
  cvssString: string
): ScoreResult => {
  const validationResult = validate(cvssString);
  const { versionStr } = validationResult;
  let { metricsMap } = validationResult;

  metricsMap = populateTemporalMetricDefaults(metricsMap);
  metricsMap = populateEnvironmentalMetricDefaults(metricsMap);

  const miss = calculateMiss(metricsMap);
  const impact = calculateModifiedImpact(metricsMap, miss, versionStr);
  const exploitability = calculateModifiedExploitability(metricsMap);
  const scopeUnchanged =
    metricsMap.get(EnvironmentalMetric.MODIFIED_SCOPE) === 'U';

  const score =
    impact <= 0
      ? 0
      : scopeUnchanged
        ? roundUp(
          roundUp(Math.min(impact + exploitability, 10)) *
          getMetricNumericValue(
            TemporalMetric.EXPLOIT_CODE_MATURITY,
            metricsMap
          ) *
          getMetricNumericValue(
            TemporalMetric.REMEDIATION_LEVEL,
            metricsMap
          ) *
          getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap)
        )
        : roundUp(
          roundUp(Math.min(1.08 * (impact + exploitability), 10)) *
          getMetricNumericValue(
            TemporalMetric.EXPLOIT_CODE_MATURITY,
            metricsMap
          ) *
          getMetricNumericValue(
            TemporalMetric.REMEDIATION_LEVEL,
            metricsMap
          ) *
          getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap)
        );

  return {
    score,
    metricsMap,
    impact: impact <= 0 ? 0 : roundUp(impact),
    exploitability: impact <= 0 ? 0 : roundUp(exploitability)
  };
};

export const calculateEnvironmentalScore = (cvssString: string): number => {
  const { score } = calculateEnvironmentalResult(cvssString);

  return score;
};

// https://www.first.org/cvss/v3.1/specification-document#7-2-Temporal-Metrics-Equations
// 	Roundup (BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
export const calculateTemporalResult = (cvssString: string): ScoreResult => {
  let { metricsMap } = validate(cvssString);
  // populate temp metrics if not provided
  metricsMap = populateTemporalMetricDefaults(metricsMap);

  const { score, impact, exploitability } = calculateBaseResult(cvssString);

  const tempScore = roundUp(
    score *
    getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap) *
    getMetricNumericValue(TemporalMetric.EXPLOIT_CODE_MATURITY, metricsMap) *
    getMetricNumericValue(TemporalMetric.REMEDIATION_LEVEL, metricsMap)
  );

  return {
    score: tempScore,
    metricsMap,
    impact,
    exploitability
  };
};

export const calculateTemporalScore = (cvssString: string): number => {
  const { score } = calculateTemporalResult(cvssString);

  return score;
};



// V4 Logic goes here ///

/**
 * Validates a CVSS vector string according to expected metrics and mandatory requirements.
 * @param {string} vectorString - The CVSS vector string to validate.
 * @returns {{ valid: boolean, error?: string, selectedMetrics?: Record<string, string> }}
 *   Returns an object indicating whether the vector is valid, with an error message if invalid.
 */
export const validateVectorV4 = (vectorString: string | null): { valid: boolean; error?: string; selectedMetrics?: Record<string, string> } => {
  let metrics = vectorString ? vectorString.split("/") : [];
  const prefix = metrics[0];
  if (prefix !== "CVSS:4.0") {
    return { valid: false, error: "Invalid vector prefix" };
  }

  metrics.shift();

  let expectedIndex = 0;
  const toSelect: any = {};
  const expectedEntries = Object.entries(expectedMetricOrder);
  const mandatoryMetrics = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

  for (const metric of metrics) {
    const [key, value] = metric.split(":");
    const expectedEntry = expectedEntries.find(entry => entry[0] === key);

    if (key in toSelect) {
      return { valid: false, error: `Invalid vector, repeated metric: ${key}` };
    }

    while (expectedIndex < expectedEntries.length && expectedEntries[expectedIndex][0] !== key) {
      expectedIndex++;
    }
    if (expectedIndex >= expectedEntries.length) {
      return { valid: false, error: `Invalid vector, metric out of sequence: ${key}` };
    }

    if (!expectedEntry) {
      return { valid: false, error: `Invalid vector, unexpected metric: ${key}` };
    }

    if (!expectedEntry[1].includes(value)) {
      return { valid: false, error: `Invalid vector, for key ${key}, value ${value} is not in [${expectedEntry[1]}]` };
    }

    toSelect[key] = value;
  }

  const missingMandatoryMetrics = mandatoryMetrics.filter(metric => !(metric in toSelect));
  if (missingMandatoryMetrics.length > 0) {
    return { valid: false, error: `Invalid vector, missing mandatory metrics: ${missingMandatoryMetrics.join(', ')}` };
  }

  return { valid: true, selectedMetrics: toSelect };
};

/**
* Parses a CVSS vector string and adds default "X" values for unspecified metrics.
* @param {string} vector - The CVSS vector string to parse.
* @returns {Record<string, string>} - An object representing the parsed and completed metrics.
*/
export const parseVectorV4 = (vector: string): Record<string, string> => {
  const metrics = vector.split('/');
  const cvssSelected: any = {};

  // Remove CVSS:4.0 prefix
  metrics.shift();

  metrics.forEach(metric => {
    const [key, value] = metric.split(':');
    cvssSelected[key] = value;
  });

  if (!("E" in cvssSelected)) {
    cvssSelected["E"] = "X";
  }
  if (!("CR" in cvssSelected)) {
    cvssSelected["CR"] = "X";
  }
  if (!("IR" in cvssSelected)) {
    cvssSelected["IR"] = "X";
  }
  if (!("AR" in cvssSelected)) {
    cvssSelected["AR"] = "X";
  }

  return cvssSelected;
};

/**
* Calculates a qualitative severity score based on the numeric CVSS score.
* @param {number} score - The numeric CVSS score.
* @returns {string} - The qualitative score: "None", "Low", "Medium", "High", or "Critical".
*/
export const calculateQualScore = (score: number): string => {
  if (score === 0) return "None";
  if (score < 4.0) return "Low";
  if (score < 7.0) return "Medium";
  if (score < 9.0) return "High";
  return "Critical";
};

/**
* Calculates the base CVSS score for version 4.0 using a vector string.
* @param {string} vectorString - The CVSS vector string to calculate the score for.
* @returns {number} - The calculated base CVSS score.
* @throws {Error} - Throws an error if the vector is invalid.
*/
export const calculateBaseScoreV4 = (vectorString: string): number => {
  const vvres = validateVectorV4(vectorString);
  if (!vvres.valid) {
    throw new Error(vvres.error);
  }
  const cvssSelected = parseVectorV4(vectorString);
  const macrov = macroVector(cvssSelected);
  let score = cvss_score(cvssSelected, cvssLookup_globalV4, maxSeverityV4, macrov);
  return score;
};












export const cvss_score = (cvssSelected: Record<string, string>, lookup: Record<string, number>, maxSeverityData: MaxSeverityData, macroVectorResult: string): number => {
  // The following defines the index of each metric's values.
  // It is used when looking for the highest vector part of the
  // combinations produced by the MacroVector respective highest vectors.
  let AV_levels = { "N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3 }
  let PR_levels = { "N": 0.0, "L": 0.1, "H": 0.2 }
  let UI_levels = { "N": 0.0, "P": 0.1, "A": 0.2 }

  let AC_levels = { 'L': 0.0, 'H': 0.1 }
  let AT_levels = { 'N': 0.0, 'P': 0.1 }

  let VC_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }
  let VI_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }
  let VA_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 }

  let SC_levels = { 'H': 0.1, 'L': 0.2, 'N': 0.3 }
  let SI_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 }
  let SA_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 }

  let CR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }
  let IR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }
  let AR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 }

  //let E_levels = { 'U': 0.2, 'P': 0.1, 'A': 0 }


  // Exception for no impact on system (shortcut)
  if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m(cvssSelected, metric) == "N")) {
    return 0.0
  }

  let value = lookup[macroVectorResult]

  // 1. For each of the EQs:
  //   a. The maximal scoring difference is determined as the difference
  //      between the current MacroVector and the lower MacroVector.
  //     i. If there is no lower MacroVector the available distance is
  //        set to NaN and then ignored in the further calculations.
  let eq1 = parseInt(macroVectorResult[0])
  let eq2 = parseInt(macroVectorResult[1])
  let eq3 = parseInt(macroVectorResult[2])
  let eq4 = parseInt(macroVectorResult[3])
  let eq5 = parseInt(macroVectorResult[4])
  let eq6 = parseInt(macroVectorResult[5])

  // compute next lower macro, it can also not exist
  let eq1_next_lower_macro = `${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  let eq2_next_lower_macro = `${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`;

  let eq3eq6_next_lower_macro = ""
  let eq3eq6_next_lower_macro_left = ""
  let eq3eq6_next_lower_macro_right = ""

  // eq3 and eq6 are related
  if (eq3 == 1 && eq6 == 1) {
    // 11 --> 21
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`;
  } else if (eq3 == 0 && eq6 == 1) {
    // 01 --> 11
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else if (eq3 == 1 && eq6 == 0) {
    // 10 --> 11
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
  } else if (eq3 == 0 && eq6 == 0) {
    // 00 --> 01
    // 00 --> 10
    eq3eq6_next_lower_macro_left = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
    eq3eq6_next_lower_macro_right = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else {
    // 21 --> 32 (do not exist)
    eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`;
  }
  let eq4_next_lower_macro = `${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`;
  let eq5_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`;
  // get their score, if the next lower macro score do not exist the result is NaN

  let score_eq1_next_lower_macro = lookup[eq1_next_lower_macro]
  let score_eq2_next_lower_macro = lookup[eq2_next_lower_macro]

  let score_eq3eq6_next_lower_macro = NaN

  if (eq3 == 0 && eq6 == 0) {
    // multiple path take the one with higher score
    let score_eq3eq6_next_lower_macro_left = lookup[eq3eq6_next_lower_macro_left]
    let score_eq3eq6_next_lower_macro_right = lookup[eq3eq6_next_lower_macro_right]

    score_eq3eq6_next_lower_macro_left = lookup[eq3eq6_next_lower_macro_left]

    if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) {
      score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
    } else {

      score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
    }
  } else {
    score_eq3eq6_next_lower_macro = lookup[eq3eq6_next_lower_macro]
  }


  let score_eq4_next_lower_macro = lookup[eq4_next_lower_macro]
  let score_eq5_next_lower_macro = lookup[eq5_next_lower_macro]

  //   b. The severity distance of the to-be scored vector from a
  //      highest severity vector in the same MacroVector is determined.
  let eq1_maxes = getEQMaxes(macroVectorResult, 1)
  let eq2_maxes = getEQMaxes(macroVectorResult, 2)
  // @ts-ignore
  let eq3_eq6_maxes = getEQMaxes(macroVectorResult, 3)[macroVectorResult[5]]
  let eq4_maxes = getEQMaxes(macroVectorResult, 4)
  let eq5_maxes = getEQMaxes(macroVectorResult, 5)

  // compose them
  // Compose them
  const max_vectors: string[] = [];
  for (let eq1_max of eq1_maxes) {
    for (let eq2_max of eq2_maxes) {
      for (let eq3_eq6_max of eq3_eq6_maxes) {
        for (let eq4_max of eq4_maxes) {
          for (let eq5_max of eq5_maxes) {
            max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5_max);
          }
        }
      }
    }
  }

  //console.log(max_vectors)
  // Find the max vector to use i.e. one in the combination of all the highests
  // that is greater or equal (severity distance) than the to-be scored vector.
  let severity_distance_AV = 0
  let severity_distance_PR = 0
  let severity_distance_UI = 0
  let severity_distance_AC = 0
  let severity_distance_AT = 0
  let severity_distance_VC = 0
  let severity_distance_VI = 0
  let severity_distance_VA = 0
  let severity_distance_SC = 0
  let severity_distance_SI = 0
  let severity_distance_SA = 0
  let severity_distance_CR = 0
  let severity_distance_IR = 0
  let severity_distance_AR = 0

  for (let i = 0; i < max_vectors.length; i++) {
    let max_vector = max_vectors[i]
    severity_distance_AV =
      AV_levels[m(cvssSelected, "AV") as keyof typeof AV_levels] -
      AV_levels[extractValueMetric("AV", max_vector) as keyof typeof AV_levels];

    severity_distance_PR =
      PR_levels[m(cvssSelected, "PR") as keyof typeof PR_levels] -
      PR_levels[extractValueMetric("PR", max_vector) as keyof typeof PR_levels];

    severity_distance_UI =
      UI_levels[m(cvssSelected, "UI") as keyof typeof UI_levels] -
      UI_levels[extractValueMetric("UI", max_vector) as keyof typeof UI_levels];

    severity_distance_AC =
      AC_levels[m(cvssSelected, "AC") as keyof typeof AC_levels] -
      AC_levels[extractValueMetric("AC", max_vector) as keyof typeof AC_levels];

    severity_distance_AT =
      AT_levels[m(cvssSelected, "AT") as keyof typeof AT_levels] -
      AT_levels[extractValueMetric("AT", max_vector) as keyof typeof AT_levels];

    severity_distance_VC =
      VC_levels[m(cvssSelected, "VC") as keyof typeof VC_levels] -
      VC_levels[extractValueMetric("VC", max_vector) as keyof typeof VC_levels];

    severity_distance_VI =
      VI_levels[m(cvssSelected, "VI") as keyof typeof VI_levels] -
      VI_levels[extractValueMetric("VI", max_vector) as keyof typeof VI_levels];

    severity_distance_VA =
      VA_levels[m(cvssSelected, "VA") as keyof typeof VA_levels] -
      VA_levels[extractValueMetric("VA", max_vector) as keyof typeof VA_levels];

    severity_distance_SC =
      SC_levels[m(cvssSelected, "SC") as keyof typeof SC_levels] -
      SC_levels[extractValueMetric("SC", max_vector) as keyof typeof SC_levels];

    severity_distance_SI =
      SI_levels[m(cvssSelected, "SI") as keyof typeof SI_levels] -
      SI_levels[extractValueMetric("SI", max_vector) as keyof typeof SI_levels];

    severity_distance_SA =
      SA_levels[m(cvssSelected, "SA") as keyof typeof SA_levels] -
      SA_levels[extractValueMetric("SA", max_vector) as keyof typeof SA_levels];

    severity_distance_CR =
      CR_levels[m(cvssSelected, "CR") as keyof typeof CR_levels] -
      CR_levels[extractValueMetric("CR", max_vector) as keyof typeof CR_levels];

    severity_distance_IR =
      IR_levels[m(cvssSelected, "IR") as keyof typeof IR_levels] -
      IR_levels[extractValueMetric("IR", max_vector) as keyof typeof IR_levels];

    severity_distance_AR =
      AR_levels[m(cvssSelected, "AR") as keyof typeof AR_levels] -
      AR_levels[extractValueMetric("AR", max_vector) as keyof typeof AR_levels];

    // if any is less than zero this is not the right max
    if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) {
      continue
    }
    // if multiple maxes exist to reach it it is enough the first one
    break
  }

  let current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
  let current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
  let current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR
  let current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA
  // let current_severity_distance_eq5 = 0

  let step = 0.1

  // if the next lower macro score do not exist the result is Nan
  // Rename to maximal scoring difference (aka MSD)
  let available_distance_eq1 = value - score_eq1_next_lower_macro
  let available_distance_eq2 = value - score_eq2_next_lower_macro
  let available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
  let available_distance_eq4 = value - score_eq4_next_lower_macro
  let available_distance_eq5 = value - score_eq5_next_lower_macro

  let percent_to_next_eq1_severity = 0
  let percent_to_next_eq2_severity = 0
  let percent_to_next_eq3eq6_severity = 0
  let percent_to_next_eq4_severity = 0
  let percent_to_next_eq5_severity = 0

  // some of them do not exist, we will find them by retrieving the score. If score null then do not exist
  let n_existing_lower = 0

  let normalized_severity_eq1 = 0
  let normalized_severity_eq2 = 0
  let normalized_severity_eq3eq6 = 0
  let normalized_severity_eq4 = 0
  let normalized_severity_eq5 = 0

  // multiply by step because distance is pure
  let maxSeverity_eq1 = maxSeverityData["eq1"][eq1] * step
  let maxSeverity_eq2 = maxSeverityData["eq2"][eq2] * step
  let maxSeverity_eq3eq6 = maxSeverityData["eq3eq6"][eq3][eq6] * step
  let maxSeverity_eq4 = maxSeverityData["eq4"][eq4] * step

  //   c. The proportion of the distance is determined by dividing
  //      the severity distance of the to-be-scored vector by the depth
  //      of the MacroVector.
  //   d. The maximal scoring difference is multiplied by the proportion of
  //      distance.
  if (!isNaN(available_distance_eq1)) {
    n_existing_lower = n_existing_lower + 1
    percent_to_next_eq1_severity = (current_severity_distance_eq1) / maxSeverity_eq1
    normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
  }

  if (!isNaN(available_distance_eq2)) {
    n_existing_lower = n_existing_lower + 1
    percent_to_next_eq2_severity = (current_severity_distance_eq2) / maxSeverity_eq2
    normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
  }

  if (!isNaN(available_distance_eq3eq6)) {
    n_existing_lower = n_existing_lower + 1
    percent_to_next_eq3eq6_severity = (current_severity_distance_eq3eq6) / maxSeverity_eq3eq6
    normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
  }

  if (!isNaN(available_distance_eq4)) {
    n_existing_lower = n_existing_lower + 1
    percent_to_next_eq4_severity = (current_severity_distance_eq4) / maxSeverity_eq4
    normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
  }

  if (!isNaN(available_distance_eq5)) {
    // for eq5 is always 0 the percentage
    n_existing_lower = n_existing_lower + 1
    percent_to_next_eq5_severity = 0
    normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
  }

  // 2. The mean of the above computed proportional distances is computed.
  let mean_distance = 0;
  if (n_existing_lower == 0) {
    mean_distance = 0
  } else { // sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
    mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower
  }

  // 3. The score of the vector is the score of the MacroVector
  //    (i.e. the score of the highest severity vector) minus the mean
  //    distance so computed. This score is rounded to one decimal place.
  value -= mean_distance;
  if (value < 0) {
    value = 0.0
  }
  if (value > 10) {
    value = 10.0
  }
  return Math.round(value * 10) / 10
}

export const getEQMaxes = (lookup: string, eq: number): string[] => {
  // @ts-ignore
  return maxComposed[`eq${eq}`][lookup[eq - 1]];
}



export const extractValueMetric = (metric: string, str: string): string => {
  // indexOf gives first index of the metric, we then need to go over its size
  let extracted = str.slice(str.indexOf(metric) + metric.length + 1)
  // remove what follow
  let metric_val = ""
  if (extracted.indexOf('/') > 0) {
    metric_val = extracted.substring(0, extracted.indexOf('/'));
  }
  else {
    // case where it is the last metric so no ending /
    metric_val = extracted
  }
  return metric_val
}

export const m = (cvssSelected: Record<string, string>, metric: string): string => {
  let selected = cvssSelected[metric]

  // If E=X it will default to the worst case i.e. E=A
  if (metric == "E" && selected == "X") {
    return "A"
  }
  // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
  if (metric == "CR" && selected == "X") {
    return "H";
  }
  // IR:X is the same as IR:H
  if (metric == "IR" && selected == "X") {
    return "H"
  }
  // AR:X is the same as AR:H
  if (metric == "AR" && selected == "X") {
    return "H"
  }

  // All other environmental metrics just overwrite base score values,
  // so if they’re not defined just use the base score value.
  if (Object.keys(cvssSelected).includes("M" + metric)) {
    let modified_selected = cvssSelected["M" + metric]
    if (modified_selected != "X") {
      return modified_selected
    }
  }

  return selected
}

export const macroVector = (cvssSelected: Record<string, string>): string => {
  // EQ1: 0-AV:N and PR:N and UI:N
  //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  //      2-AV:P or not(AV:N or PR:N or UI:N)

  let eq1 = 0
  let eq2 = 0
  let eq3 = 0
  let eq4 = 0
  let eq5 = 0
  let eq6 = 0

  if (m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N") {
    eq1 = 0
  }
  else if ((m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")
    && !(m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N")
    && !(m(cvssSelected, "AV") == "P")) {
    eq1 = 1
  }
  else if (m(cvssSelected, "AV") == "P"
    || !(m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")) {
    eq1 = 2
  }

  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))

  if (m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N") {
    eq2 = 0
  }
  else if (!(m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N")) {
    eq2 = 1
  }

  // EQ3: 0-(VC:H and VI:H)
  //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
  //      2-not (VC:H or VI:H or VA:H)
  if (m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H") {
    eq3 = 0
  }
  else if (!(m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H")
    && (m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
    eq3 = 1
  }
  else if (!(m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
    eq3 = 2
  }

  // EQ4: 0-(MSI:S or MSA:S)
  //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

  if (m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") {
    eq4 = 0
  }
  else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
    (m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H")) {
    eq4 = 1
  }
  else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
    !((m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H"))) {
    eq4 = 2
  }

  // EQ5: 0-E:A
  //      1-E:P
  //      2-E:U

  if (m(cvssSelected, "E") == "A") {
    eq5 = 0
  }
  else if (m(cvssSelected, "E") == "P") {
    eq5 = 1
  }
  else if (m(cvssSelected, "E") == "U") {
    eq5 = 2
  }

  // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

  if ((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
    || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
    || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H")) {
    eq6 = 0
  }
  else if (!((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
    || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
    || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H"))) {
    eq6 = 1
  }

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`
}
