import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';

// Convert CVSS vector value to human-readable description
export const getVectorDescription = (metric: string, value: string): string => {
    if (!value || value === 'X') return 'Not Defined';
    
    switch (metric) {
        case 'AV': // Attack Vector
            switch (value) {
                case 'N': return 'Network Accessible';
                case 'A': return 'Adjacent Network';
                case 'L': return 'Local Access';
                case 'P': return 'Physical Access';
                default: return value;
            }
        case 'AC': // Attack Complexity
            switch (value) {
                case 'L': return 'Low Complexity';
                case 'H': return 'High Complexity';
                default: return value;
            }
        case 'AT': // Attack Requirements (CVSS v4)
            switch (value) {
                case 'N': return 'No Attack Requirements';
                case 'P': return 'Present Attack Requirements';
                default: return value;
            }
        case 'PR': // Privileges Required
            switch (value) {
                case 'N': return 'No Privileges Required';
                case 'L': return 'Low Privileges Required';
                case 'H': return 'High Privileges Required';
                default: return value;
            }
        case 'UI': // User Interaction
            switch (value) {
                case 'N': return 'No User Interaction';
                case 'R': return 'Requires User Interaction';
                case 'A': return 'Active User Interaction';
                case 'P': return 'Passive User Interaction';
                default: return value;
            }
        case 'VC': // Vulnerable System Confidentiality (CVSS v4)
            switch (value) {
                case 'H': return 'High Confidentiality Impact';
                case 'L': return 'Low Confidentiality Impact';
                case 'N': return 'No Confidentiality Impact';
                default: return value;
            }
        case 'VI': // Vulnerable System Integrity (CVSS v4)
            switch (value) {
                case 'H': return 'High Integrity Impact';
                case 'L': return 'Low Integrity Impact';
                case 'N': return 'No Integrity Impact';
                default: return value;
            }
        case 'VA': // Vulnerable System Availability (CVSS v4)
            switch (value) {
                case 'H': return 'High Availability Impact';
                case 'L': return 'Low Availability Impact';
                case 'N': return 'No Availability Impact';
                default: return value;
            }
        case 'C': // Confidentiality Impact (CVSS v3)
            switch (value) {
                case 'H': return 'High Confidentiality Impact';
                case 'L': return 'Low Confidentiality Impact';
                case 'N': return 'No Confidentiality Impact';
                default: return value;
            }
        case 'I': // Integrity Impact (CVSS v3)
            switch (value) {
                case 'H': return 'High Integrity Impact';
                case 'L': return 'Low Integrity Impact';
                case 'N': return 'No Integrity Impact';
                default: return value;
            }
        case 'A': // Availability Impact (CVSS v3)
            switch (value) {
                case 'H': return 'High Availability Impact';
                case 'L': return 'Low Availability Impact';
                case 'N': return 'No Availability Impact';
                default: return value;
            }
        case 'E': // Exploit Code Maturity
            switch (value) {
                case 'A': return 'Automated Exploit Available';
                case 'F': return 'Functional Exploit Available';
                case 'P': return 'Proof-of-Concept Exploit Available';
                case 'U': return 'Unproven Exploit';
                default: return value;
            }
        case 'RL': // Remediation Level
            switch (value) {
                case 'O': return 'Official Fix Available';
                case 'T': return 'Temporary Fix Available';
                case 'W': return 'Workaround Available';
                case 'U': return 'Unavailable Remediation';
                default: return value;
            }
        case 'RC': // Report Confidence
            switch (value) {
                case 'C': return 'Confirmed Report';
                case 'R': return 'Reasonable Report Confidence';
                case 'U': return 'Unknown Report Confidence';
                default: return value;
            }
        case 'S': // Safety (CVSS v4)
            switch (value) {
                case 'P': return 'Present Safety Impact';
                case 'N': return 'Negligible Safety Impact';
                default: return value;
            }
        case 'AU': // Automatable (CVSS v4)
            switch (value) {
                case 'Y': return 'Automatable Attack';
                case 'N': return 'Not Automatable';
                default: return value;
            }
        case 'U': // Provider Urgency (CVSS v4)
            switch (value) {
                case 'Clear': return 'Clear Provider Urgency';
                case 'Green': return 'Green Provider Urgency';
                case 'Amber': return 'Amber Provider Urgency';
                case 'Red': return 'Red Provider Urgency';
                default: return value;
            }
        default:
            return value;
    }
};

// Get metric name description
export const getMetricName = (metric: string): string => {
    switch (metric) {
        case 'AV': return 'Attack Vector';
        case 'AC': return 'Attack Complexity';
        case 'AT': return 'Attack Requirements';
        case 'PR': return 'Privileges Required';
        case 'UI': return 'User Interaction';
        case 'VC': return 'Vulnerable System Confidentiality';
        case 'VI': return 'Vulnerable System Integrity';
        case 'VA': return 'Vulnerable System Availability';
        case 'C': return 'Confidentiality Impact';
        case 'I': return 'Integrity Impact';
        case 'A': return 'Availability Impact';
        case 'E': return 'Exploit Code Maturity';
        case 'RL': return 'Remediation Level';
        case 'RC': return 'Report Confidence';
        case 'S': return 'Safety';
        case 'AU': return 'Automatable';
        case 'U': return 'Provider Urgency';
        default: return metric;
    }
};

// Get severity color based on CVSS/CWSS score
// Returns Vuetify color names for consistent theming
export const getSeverityColor = (score: number): 'success' | 'info' | 'warning' | 'error' => {
    if (score < 4.0) return 'success';
    if (score < 7.0) return 'info';
    if (score < 9.0) return 'warning';
    return 'error';
};

// Detect CVSS version from vector string
export const detectCvssVersion = (vectorString: string | null | undefined): '3.0' | '3.1' | '4.0' | null => {
    if (!vectorString || typeof vectorString !== 'string') {
        return null;
    }
    
    if (vectorString.startsWith('CVSS:3.0/')) return '3.0';
    if (vectorString.startsWith('CVSS:3.1/')) return '3.1';
    if (vectorString.startsWith('CVSS:4.0/')) return '4.0';
    
    return null;
};

// Compute CVSS score from any vector string version
// Supports CVSS v3.0, v3.1, and v4.0
// Returns null if vector string is invalid or unsupported
export const computeCvssScore = (vectorString: string | null | undefined, decimalPlaces: number = 1): string | null => {
    if (!vectorString || typeof vectorString !== 'string') {
        return null;
    }

    try {
        // CVSS v3.1
        if (vectorString.startsWith('CVSS:3.1/')) {
            const cvss = new CVSS31(vectorString);
            return cvss.BaseScore().toFixed(decimalPlaces);
        }

        // CVSS v3.0
        if (vectorString.startsWith('CVSS:3.0/')) {
            const cvss = new CVSS30(vectorString);
            return cvss.BaseScore().toFixed(decimalPlaces);
        }

        // CVSS v4.0
        if (vectorString.startsWith('CVSS:4.0/')) {
            const cvss = new CVSS40(vectorString);
            return cvss.Score().toFixed(decimalPlaces);
        }

        // Unsupported version or format
        return null;
    } catch (error) {
        // Invalid vector string format - silently return null in production
        return null;
    }
};

/**
 * Convert CVSS v2.0 vector string to CVSS v3.1 equivalent
 *
 * This provides a best-effort mapping for legacy CVEs that only have CVSS v2 scores.
 * The conversion uses documented mappings between CVSS v2 and v3 metrics.
 *
 * Mapping reference:
 * - Access Vector (AV): Local=L, Adjacent=A, Network=N -> Attack Vector (AV)
 * - Access Complexity (AC): High=H, Medium/Low=L -> Attack Complexity (AC)
 * - Authentication (Au): Multiple=H, Single=L, None=N -> Privileges Required (PR)
 * - Confidentiality/Integrity/Availability Impact: None=N, Partial=L, Complete=H -> C/I/A
 * - User Interaction (UI): Defaults to N (None) for v2 conversions
 * - Scope (S): Defaults to U (Unchanged) for v2 conversions
 *
 * @param v2VectorString CVSS v2.0 vector string (e.g., "AV:N/AC:L/Au:N/C:P/I:P/A:P")
 * @returns CVSS v3.1 vector string or null if conversion fails
 *
 * @example
 * convertCvssV2ToV31("AV:N/AC:L/Au:N/C:P/I:P/A:P")
 * // Returns: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
 */
export const convertCvssV2ToV31 = (v2VectorString: string | null | undefined): string | null => {
    if (!v2VectorString || typeof v2VectorString !== 'string') {
        return null;
    }

    try {
        // Parse CVSS v2 vector string
        // Format: "AV:X/AC:X/Au:X/C:X/I:X/A:X"
        const metrics: Record<string, string> = {};
        const parts = v2VectorString.split('/');

        for (const part of parts) {
            const [key, value] = part.split(':');
            if (key && value) {
                metrics[key.trim()] = value.trim();
            }
        }

        // Validate we have the required v2 metrics
        if (!metrics.AV || !metrics.AC || !metrics.Au || !metrics.C || !metrics.I || !metrics.A) {
            return null;
        }

        // Map Access Vector (AV) to Attack Vector (AV)
        // v2: L=Local, A=Adjacent Network, N=Network
        // v3: L=Local, A=Adjacent, N=Network, P=Physical (new in v3)
        let av = metrics.AV;
        // Direct mapping works for AV

        // Map Access Complexity (AC) to Attack Complexity (AC)
        // v2: H=High, M=Medium, L=Low
        // v3: H=High, L=Low (Medium is mapped to Low)
        let ac = 'L';
        if (metrics.AC === 'H') {
            ac = 'H';
        }

        // Map Authentication (Au) to Privileges Required (PR)
        // v2: M=Multiple, S=Single, N=None
        // v3: H=High, L=Low, N=None
        let pr = 'N';
        if (metrics.Au === 'M') {
            pr = 'H'; // Multiple instances of authentication -> High privileges
        } else if (metrics.Au === 'S') {
            pr = 'L'; // Single instance of authentication -> Low privileges
        }

        // User Interaction (UI) - New in v3, defaults to None for v2 conversions
        // v3: N=None, R=Required
        const ui = 'N';

        // Scope (S) - New in v3, defaults to Unchanged for v2 conversions
        // v3: U=Unchanged, C=Changed
        const s = 'U';

        // Map Impact metrics (Confidentiality, Integrity, Availability)
        // v2: N=None, P=Partial, C=Complete
        // v3: N=None, L=Low, H=High
        const mapImpact = (v2Impact: string): string => {
            switch (v2Impact) {
                case 'N': return 'N'; // None -> None
                case 'P': return 'L'; // Partial -> Low
                case 'C': return 'H'; // Complete -> High
                default: return 'N';
            }
        };

        const c = mapImpact(metrics.C);
        const i = mapImpact(metrics.I);
        const a = mapImpact(metrics.A);

        // Construct CVSS v3.1 vector string
        const v31Vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

        // Validate the generated v3.1 vector by attempting to parse it
        try {
            new CVSS31(v31Vector);
            return v31Vector;
        } catch (error) {
            // Generated vector is invalid
            return null;
        }
    } catch (error) {
        // Conversion failed
        return null;
    }
};
