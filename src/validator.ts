import {
  BaseMetric,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  Metrics,
  TemporalMetric,
  baseMetricValues,
  baseMetrics,
  environmentalMetricValues,
  environmentalMetrics,
  expectedMetricOrder,
  temporalMetricValues,
  temporalMetrics
} from './models';
import { humanizeBaseMetric, humanizeBaseMetricValue } from './humanizer';
import { parseMetricsAsMap, parseVector, parseVersion } from './parser';


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


export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }

  if (versionStr !== '3.0' && versionStr !== '3.1' && versionStr !== '4.0') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported`
    );
  }
};

const validateVector = (vectorStr: string | null): void => {
  if (!vectorStr || vectorStr.includes('//')) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }
};

const checkUnknownMetrics = (
  metricsMap: Map<string, string>,
  knownMetrics?: Metrics
): void => {
  const allKnownMetrics = knownMetrics || [
    ...baseMetrics,
    ...temporalMetrics,
    ...environmentalMetrics
  ];

  [...metricsMap.keys()].forEach((userMetric: string) => {
    if (!allKnownMetrics.includes(userMetric as Metric)) {
      throw new Error(
        `Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(
          ', '
        )}`
      );
    }
  });
};

const checkMandatoryMetrics = (
  metricsMap: Map<string, string>,
  metrics: ReadonlyArray<BaseMetric> = baseMetrics
): void => {
  metrics.forEach((metric: Metric) => {
    if (!metricsMap.has(metric)) {
      // eslint-disable-next-line max-len
      throw new Error(
        `Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(
          metric
        )})`
      );
    }
  });
};

const checkMetricsValues = (
  metricsMap: Map<string, string>,
  metrics: Metrics,
  metricsValues: Record<Metric, MetricValue[]>
): void => {
  metrics.forEach((metric: Metric) => {
    const userValue = metricsMap.get(metric);
    if (!userValue) {
      return;
    }
    if (!metricsValues[metric].includes(userValue as MetricValue)) {
      const allowedValuesHumanized = metricsValues[metric]
        .map(
          (value: MetricValue) =>
            `${value} (${humanizeBaseMetricValue(value, metric)})`
        )
        .join(', ');
      throw new Error(
        `Invalid value for CVSS metric ${metric} (${humanizeBaseMetric(
          metric
        )})${userValue ? `: ${userValue}` : ''
        }. Allowed values: ${allowedValuesHumanized}`
      );
    }
  });
};

type ValidationResult = {
  isTemporal: boolean;
  isEnvironmental: boolean;
  metricsMap: Map<Metric, MetricValue>;
  versionStr: string | null;
};

/**
 * Validate that the given string is a valid cvss vector
 * @param cvssStr
 */
export const validate = (cvssStr: string): ValidationResult => {
  if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
    throw new Error('CVSS vector must start with "CVSS:"');
  }
  if (cvssStr.startsWith('CVSS:4')) {
    validateVectorV4(cvssStr);
  }
  const allKnownMetrics = [
    ...baseMetrics,
    ...temporalMetrics,
    ...environmentalMetrics
  ];
  const allKnownMetricsValues = {
    ...baseMetricValues,
    ...temporalMetricValues,
    ...environmentalMetricValues
  };

  const versionStr = parseVersion(cvssStr);
  validateVersion(versionStr);

  const vectorStr = parseVector(cvssStr);
  validateVector(vectorStr);

  const metricsMap = parseMetricsAsMap(cvssStr);
  checkMandatoryMetrics(metricsMap);
  checkUnknownMetrics(metricsMap, allKnownMetrics);
  checkMetricsValues(metricsMap, allKnownMetrics, allKnownMetricsValues);

  const isTemporal = [...metricsMap.keys()].some((metric) =>
    temporalMetrics.includes(metric as TemporalMetric)
  );
  const isEnvironmental = [...metricsMap.keys()].some((metric) =>
    environmentalMetrics.includes(metric as EnvironmentalMetric)
  );
  return {
    metricsMap,
    isTemporal,
    isEnvironmental,
    versionStr
  };
}