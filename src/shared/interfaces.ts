import type {
    Finding,
    GitHubBranch,
    GitHubRepository,
    PrismaClient,
    Report,
    Session,
    TriagePolicy
} from '@prisma/client';
import type { JWTPayload, JWTVerifyResult } from 'jose';

export type bomFormat = 'CycloneDX' | 'SPDX' | 'SARIF' | 'VEX' | 'Unknown' | 'Multiple' | 'None' | 'all';
export type artifactType = 'BOM' | 'ATTESTATION' | 'VDR' | 'VEX' | 'OTHER' | 'Unknown' | 'all';
export type GitHubRepositoryVisibility = 'public' | 'private';
export interface Request {
    headers: Headers;
    body: string;
    method: string;
    url: string;
    cf: {
        tlsVersion: string;
        botManagement: {
            verifiedBot: boolean;
            score: number;
        };
    };
    userAgent: string;
}

export interface Context {
    request: Request;
    next: CallableFunction;
    env: Env;
    params?: {
        email?: string;
        hash?: string;
        org?: string;
        source?: string;
        visibility?: string;
        tei?: string;
        collectionId?: string;
        reportId?: string;
        installationId?: string;
        patId?: string;
        apiKey?: string;
        suspend?: string;
        orgId?: string;
        memberUuid?: string;
        memberEmail?: string;
        memberPassword?: string;
        memberFirstName?: string;
        memberLastName?: string;
        memberAlertFindings?: string;
        memberAlertType?: string;
        memberAlertNews?: string;
        memberAlertOverdue?: string;
        uuid?: string;
        repo?: string;
        oauthId?: string;
        policyUuid?: string;
        collectionUuid?: string;
        code?: string;
        installation_id?: string;
        requirementUuid?: string;
        reportTypeUuid?: string;
        reportUuid?: string;
    };
    data: {
        cfzt: JWTPayload;
        jwtVerifyResult: JWTVerifyResult;
        cfAuthToken?: string;
        json: any;
        prisma: PrismaClient;
        session: Session;
        authManager: any; // AuthManager from shared/auth.ts
        logger: {
            warn: (message: string, data?: any) => void;
            debug: (message: string, data?: any) => void;
            error: (message: string, data?: any) => void;
            info: (message: string, data?: any) => void;
        };
        searchParams: URLSearchParams;
        body: string;
    };
}

export interface FetchResponse {
    ok: boolean;
    status?: number;
    statusText?: string;
    tokenExpiry?: number;
    error?: {
        message?: string;
        lineno?: number;
        colno?: number;
        retryAfter?: number;
    };
    content?: any;
    url?: URL | string;
    raw?: string;
    rateLimitRemaining?: number;
    rateLimitReset?: number;
}

export interface FindingData {
    uuid: string;
    findingId: string;
    orgId: string;
    repoName?: string;
    source: string;
    category: string;
    createdAt: number;
    modifiedAt: number;
    detectionTitle: string;
    detectionDescription?: string;
    packageName: string;
    packageVersion?: string;
}

export interface TriageData {
    uuid: string;
    findingUuid: string;
    createdAt: number;
    lastObserved: number;
    seen: number;
    analysisState: string;
    triageAutomated: number;
}

export interface SarifRule {
    id: string;
    defaultConfiguration?: {
        level?: string;
    };
    fullDescription: {
        text: string;
    };
    help?: {
        markdown?: string;
        text?: string;
    };
    properties?: {
        'security-severity'?: string;
        precision?: string;
        tags?: string[];
    };
}

export interface SarifData {
    sarifId: string;
    reportId: string;
    source: string;
    createdAt: number;
    resultsCount: number;
    rulesCount: number;
    toolName: string;
    toolVersion: string;
    results?: ResultData[];
    commitSha?: string;
    ref?: string;
    analysisKey?: string;
    warning?: string;
}

export interface ResultData {
    guid: string;
    reportId: string;
    messageText: string;
    ruleId: string;
    locations: string;
    automationDetailsId?: string;
    rulesetName?: string;
    level?: string;
    description?: string;
    helpMarkdown?: string;
    securitySeverity?: string;
    precision?: string;
    tags?: string;
}

export type StepStatus = 'success' | 'info' | 'warning' | 'error' | '';

// Re-export Prisma types for convenience (but prefer importing directly from @prisma/client)
export type {
    Artifact,
    CVEMetadataReferences,
    Finding,
    FindingReferences,
    GitHubBranch,
    GitHubRepository,
    Org,
    Report, ReportingInstructions, ReportType,
    Requirement,
    RequirementResult,
    RequirementScope, Session,
    TestingProcedure,
    TestingProcedureResult,
    TriagePolicy
} from '@prisma/client';

export interface CVEMetadata {
    cveId: string;
    dataVersion: string;
    state: string;
    datePublished: number;
    dateUpdated?: number;
    dateReserved?: number;
    vectorString?: string;
    title: string;
    sourceAdvisoryRef?: string;
    affectedVendor?: string;
    affectedProduct?: string;
    affectedVersionsJSON?: string;
    cpesJSON?: string;
    cnaOrgId: string;
    createdAt: number;
}

export interface CVENumberingAuthority {
    orgId: string;
    shortName: string;
}

export interface CVEADP {
    cveId: string;
    adpId: string;
}

export interface AuthorizedDataPublisher {
    orgId: string;
    shortName: string;
    title: string;
}

export interface PCITestingProcedure {
    uuid: string
    title: string;
    description: string
    reportingInstructions: string[]
    reportingDetails: string
}

export interface RepositoryScope {
    uuid: string
    orgId: string
    repoName: string
    repo: GitHubRepository
}

export interface StepStatuses {
    step1: StepStatus
    step2: StepStatus
    step3: StepStatus
    step4: StepStatus
}

export interface PCIRequirement {
    uuid: string
    title: string
    description: string
    detail?: string
    testingProcedures: PCITestingProcedure[]
    assessmentFinding: 'In Place' | 'Not Applicable' | 'Not Tested' | 'Not in Place'
    method?: 'Compensating Control' | 'Customized Approach' | 'Standard Approach'
    currentlyBestPractice: boolean;
    serviceProvidersOnly: boolean;
    repositories: RepositoryScope[],
    stepStatus?: StepStatuses
}

export interface Summary {
    currentReport: Report;
    reports: Report[];
    assessmentDueDate: number;
}

export interface GitHubRepositoryStats {
    ghid: string;
    fullName: string;
    repoName?: string;
    orgName?: string;
    defaultBranch: string;
    fork: boolean;
    archived: boolean;
    visibility: GitHubRepositoryVisibility;
    template: boolean;
    licenseName?: string;
    licenseSpdxId?: string;
    createdAt: string;
    updatedAt: string;
    pushedAt: string;
    avatarUrl: string;
    securityInsights?: {
        findings_critical: number;
        findings_high: number;
        findings_low: number;
        findings_patchable: number;
        policy_violations: {
            critical_overdue: number;
            high_overdue: number;
            remediation_overdue: number;
        };
    };
}

export interface RepositoriesState {
    loadingBar: boolean;
    gitRepos: GitHubRepositoryStats[];
    refreshLoaders: Record<string, boolean>;
    sync: number;
    totalPromises: number;
    aggregates: RepoAggregates[];
}

export interface ActivityDay {
    date: Date;
    count: number;
}

export interface MonthLabel {
    key: number;
    label: string;
    left: number;
}

export interface OrgGroup {
    orgName: string;
    avatarUrl: string;
    repos: GitHubRepositoryStats[];
}

export interface OrgSettings {
    enforceGitHubOAuth: number;
    enforceCompanyDomain: string | null;
    triagePolicies: string[];
}

export interface RepoAggregates {
    policy: TriagePolicy;
    severityDistribution: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        informational: number;
    };
    policyViolations: {
        remediationThresholdViolations: number;
        triageThresholdViolations: number;
        triageUnratedViolations: number;
        exposureWindowViolations: number;
        threatWindowViolations: number;
    };
    totalFindingsWithTriages: number;
    projectToSeverity: Array<{ project: string; severity: string; count: number }>;
    severityToViolation: Array<{ severity: string; violationType: string; count: number }>;
    projectToViolation: Array<{ project: string; violationType: string; count: number }>;
}

export interface ExtendedRepoStatsAggregates {
    repoCount: number;
    monitoredRepoCount: number;
    findingCount: number;
    triagedCount: number;
    exploitableCount: number;
    automatableFixCount: number;
    uniqueOwnerCount: number;
    uniqueLicenseCount: number;
    archivedCount: number;
    forkCount: number;
    publicCount: number;
    privateCount: number;
    monitoredBranchCount: number;
    sources: string[];
    artifactCount: number;
    linkCount: number;
}

// TEA (Transparency Exchange API) Interfaces
export interface TeaIdentifier {
    idType: 'cpe' | 'tei' | 'purl' | 'swid';
    idValue: string;
}

export interface UpdateTeaComponentRequest {
    name?: string;
    barcode?: string;
    sku?: string;
    vendor?: string;
    identifiers?: TeaIdentifier[];
    type?: string;
    namespace?: string;
    version?: string;
    qualifiers?: Record<string, string>[];
    subpath?: string;
}

export interface TeaComponent {
    identifier: string;
    name: string;
    barcode?: string;
    sku?: string;
    vendor?: string;
    identifiers: TeaIdentifier[];
    type: string;
    namespace?: string;
    version?: string;
    qualifiers?: Record<string, string>[];
    subpath?: string;
}

export interface UpdateTeaProductRequest {
    name?: string;
    barcode?: string;
    sku?: string;
    vendorUuid?: string;
    identifiers?: TeaIdentifier[];
    type?: string;
    namespace?: string;
    version?: string;
    qualifiers?: string;
    subpath?: string;
}

export interface TeaProduct {
    identifier: string;
    name: string;
    barcode?: string;
    sku?: string;
    vendorUuid?: string;
    identifiers: TeaIdentifier[];
    type: string;
    namespace?: string;
    version?: string;
    qualifiers?: Record<string, string>[];
    subpath?: string;
    components: string[];
}

export interface UpdateTeaReleaseRequest {
    tag?: string;
    version?: string;
    name?: string;
    description?: string;
    releaseDate?: string;
    validUntilDate?: string;
    prerelease?: boolean;
    draft?: boolean;
}

export interface TeaRelease {
    identifier: string;
    productUuid: string;
    tag: string;
    version?: string;
    name?: string;
    description?: string;
    releaseDate?: string;
    validUntilDate?: string;
    prerelease: boolean;
    draft: boolean;
    components: string[];
}

export interface TeaArtifact {
    name: string;
    downloadUrl: string;
    checksums?: Record<string, string>;
}

export interface TeaLifecycle {
    phase: string;
    name?: string;
    description?: string;
    startedOn?: string;
    completedOn?: string;
}

export interface CreateTeaCollectionRequest {
    releaseIdentifier: string;
    updateReason: {
        type: string;
        comment?: string;
    };
    artifacts?: TeaArtifact[];
}

export interface TeaCollection {
    identifier: string;
    name: string;
    description?: string;
    artifacts?: TeaArtifact[];
    lifecycle?: TeaLifecycle;
    products: string[];
}

export interface CreateTeaComponentRequest {
    productIdentifier: string;
    name: string;
    barcode?: string;
    sku?: string;
    vendor?: string;
    identifiers?: TeaIdentifier[];
    type: string;
    namespace?: string;
    version?: string;
    qualifiers?: Record<string, string>[];
    subpath?: string;
}

export interface CreateTeaProductRequest {
    name: string;
    barcode?: string;
    sku?: string;
    vendorUuid?: string;
    identifiers?: TeaIdentifier[];
    type: string;
    namespace?: string;
    version?: string;
    qualifiers?: Record<string, string>[];
    subpath?: string;
}

export interface CreateTeaReleaseRequest {
    componentIdentifier: string;
    version: string;
    releaseDate: string;
    preRelease?: boolean;
    identifiers?: TeaIdentifier[];
}

export interface UpdateTeaCollectionRequest {
    name?: string;
    description?: string;
    artifacts?: TeaArtifact[];
    lifecycle?: TeaLifecycle;
}

export interface RepoStats {
    findingSourceCategories: Set<string>;
    artifactCount: number;
    findingCount: number;
    triagedCount: number;
    exploitableCount: number;
    automatableFixCount: number;
    monitoredBranches: Set<string>;
}

export interface TriagePolicyMetrics {
    policy: TriagePolicy;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    informationalCount: number;
    overdueRemediationCount: number;
    overdueTriageCount: number;
    overdueExposureWindowCount: number;
    overdueThreatWindowCount: number;
}

// Methodology mapping UI types
export interface FieldDescriptor {
    key: string;
    label: string;
    // Category of the field. Primarily informative for clients.
    source: 'finding' | 'triage' | 'computed' | 'dependency' | 'sarif';
}

// JSON value type for matching logic payloads
export type JSONPrimitive = string | number | boolean | null;
export type JSONValue = JSONPrimitive | JSONObject | JSONArray;
export interface JSONObject { [key: string]: JSONValue }
export interface JSONArray extends Array<JSONValue> {}

export interface MethodologyMappingResponse {
    success: boolean;
    savedMappings: Record<string, string>;
    fullMappings?: Record<string, {
        fields: Array<{
            fieldKey: string;
            defaultTargetValue?: string;
            orderIndex?: number;
            enabled?: boolean;
            // Optional when mapping to an external integration rather than a simple field
            fieldSource?: 'FIELD' | 'INTEGRATION';
            integrationProvider?: string; // e.g., 'snyk', 'osv'
            rules?: Array<{
                orderIndex?: number;
                operator: 'EQ' | 'NEQ' | 'GT' | 'GTE' | 'LT' | 'LTE' | 'BETWEEN' | 'IN' | 'CONTAINS';
                valueString?: string;
                valueList?: string[];
                minValue?: number;
                maxValue?: number;
                targetValue: string;
                enabled?: boolean;
                // Optional advanced matcher configuration
                matcherType?: 'FIELD' | 'JSON_PATH' | 'REGEX' | 'GLOB';
                matcherExpr?: string; // JSONPath/regex/glob pattern depending on matcherType
            }>;
        }>;
    }>;
    availableFields: FieldDescriptor[];
    availableIntegrations?: Array<{ key: string; label: string }>;
}

export interface MethodologyCoverage {
    mappedCount: number;
    totalCount: number;
    complete: number; // 1 if fully mapped, else 0
}

export interface GitHubRepositoryWithStats extends GitHubRepository {
    findings: Finding[];
    branches: GitHubBranch[];
    stats: RepoStats;
    policyMetrics: TriagePolicyMetrics[];
}

// Enhanced Inventory Interfaces
export interface DependencyMetrics {
    totalDependencies: number;
    directDependencies: number;
    indirectDependencies: number;
    ecosystemDistribution: Array<{
        ecosystem: string;
        count: number;
        vulnerableCount: number;
    }>;
    licenseDistribution: Array<{
        license: string;
        count: number;
    }>;
    topVulnerablePackages: Array<{
        packageName: string;
        ecosystem: string;
        vulnerabilityCount: number;
        severity: string;
    }>;
}

export interface DevelopmentMetrics {
    languageDistribution: Array<{
        language: string;
        repositoryCount: number;
        percentage: number;
    }>;
    repositoryActivity: {
        activeRepos: number;
        staleRepos: number;
        recentlyCreated: number;
    };
    contributorMetrics: {
        totalContributors: number;
        avgContributorsPerRepo: number;
        topContributors: Array<{
            login: string;
            contributionCount: number;
            repositoryCount: number;
        }>;
    };
    branchMetrics: {
        totalBranches: number;
        protectedBranches: number;
        monitoredBranches: number;
    };
}

export interface CatalogMetrics {
    totalCatalogItems: number;
    catalogItemTypeDistribution: Array<{
        type: string;
        count: number;
        repositoryCount: number;
    }>;
    organizationStructure: {
        teamsCount: number;
        projectsCount: number;
        productsCount: number;
        campaignsCount: number;
        groupsCount: number;
    };
    ownership: {
        catalogItemsWithOwners: number;
        catalogItemsWithLeads: number;
        topOwners: Array<{
            email: string;
            catalogItemsOwned: number;
            catalogItemsLed: number;
        }>;
    };
    tags: {
        totalTags: number;
        taggedCatalogItems: number;
        untaggedCatalogItems: number;
        topTags: Array<{
            name: string;
            catalogItemCount: number;
        }>;
    };
    repositoryAssignment: {
        assignedRepositories: number;
        unassignedRepositories: number;
        multiAssignedRepositories: number;
    };
}

export interface InventoryMetrics {
    dependencies: DependencyMetrics;
    development: DevelopmentMetrics;
    catalog: CatalogMetrics;
}

export interface CostAnalysisData {
    totalInputCost: number;
    totalOutputCost: number;
    totalCost: number;
    totalPromptTokens: number;
    totalCompletionTokens: number;
    totalTokens: number;
    recordCount: number;
    timeSeriesData: Array<{
        date: string;
        promptTokens: number;
        completionTokens: number;
        inputCost: number;
        outputCost: number;
        totalCost: number;
    }>;
}

export interface CvssOption {
    id: string
    label: string
    source: string
    vectorString: string
    cvssVersion: string
}

// ============================================================================
// CVE Record Creation Form Interfaces
// ============================================================================

/**
 * CVE Metadata form data - Core fields for CVE record
 */
export interface CVEMetadataForm {
    cveId: string // CVE-YYYY-NNNNN format
    source: string // cve.org, osv, github, etc.
    dataVersion: string // Default: 5.1.1
    state: `PUBLISHED` | `REJECTED` | `RESERVED`
    datePublished: number // Unix timestamp
    dateUpdated?: number // Unix timestamp
    dateReserved?: number // Unix timestamp
    title?: string
    sourceAdvisoryRef?: string // Advisory URL
}

/**
 * CNA (CVE Numbering Authority) form data
 */
export interface CVECNAForm {
    orgId: string // UUID format
    shortName: string // 2-32 characters
}

/**
 * ADP (Authorized Data Publisher) form data
 */
export interface CVEADPForm {
    orgId: string // UUID format
    shortName: string
    title: string
}

/**
 * CVE Reference form data - URLs with metadata
 */
export interface CVEReferenceForm {
    uuid?: string // For UI tracking
    url: string
    type: string // advisory, article, exploit, tool, etc.
    referenceSource: string // Source that provided this reference
    title?: string
}

/**
 * CVE Problem Type form data - CWE classifications
 */
export interface CVEProblemTypeForm {
    uuid?: string // For UI tracking
    cweId?: string // e.g., CWE-79
    description: string
    descriptionType: string // text, CWE, other
    lang: string // BCP 47 language code
    containerType: `cna` | `adp`
    adpOrgId?: string // If containerType is adp
}

/**
 * CVE Metric form data - CVSS and other scoring
 */
export interface CVEMetricForm {
    uuid?: string // For UI tracking
    metricType: `cvssV2_0` | `cvssV3_0` | `cvssV3_1` | `cvssV4_0` | `ssvc` | `other`
    vectorString?: string
    baseScore?: number // 0.0-10.0
    baseSeverity?: `NONE` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
    metricFormat?: string
    scenariosJSON?: string // JSON array
    otherType?: string // For other metricType
    otherContent?: string // JSON for other metricType
    containerType: `cna` | `adp`
    adpOrgId?: string // If containerType is adp
}

/**
 * CVE Affected Version form data
 */
export interface CVEAffectedVersionForm {
    uuid?: string // For UI tracking
    version: string
    status: `affected` | `unaffected` | `unknown`
    versionType?: string // semver, custom, git, maven, etc.
    lessThan?: string // For range
    lessThanOrEqual?: string // For range
    changes?: string // JSON array of version status changes
}

/**
 * CVE Affected Product form data
 */
export interface CVEAffectedForm {
    uuid?: string // For UI tracking
    vendor?: string
    product?: string
    collectionURL?: string // Alternative to vendor+product
    packageName?: string
    cpes?: string[] // Array of CPE strings
    modules?: string[] // Array of module names
    programFiles?: string[] // Array of file paths
    programRoutines?: string[] // Array of function names
    platforms?: string[] // Array of platform names
    repo?: string // Repository URL
    defaultStatus?: `affected` | `unaffected` | `unknown`
    versions: CVEAffectedVersionForm[]
    containerType: `cna` | `adp`
    adpOrgId?: string // If containerType is adp
}

/**
 * CVE Description form data - Multi-language support
 */
export interface CVEDescriptionForm {
    uuid?: string // For UI tracking
    lang: string // BCP 47 language code
    value: string // Description text
    supportingMedia?: string // JSON array of media references
    containerType: `cna` | `adp`
    adpOrgId?: string // If containerType is adp
}

/**
 * Complete CVE form data - All steps combined
 */
export interface CVEFormData {
    // Step 1: Core metadata
    metadata: CVEMetadataForm

    // Step 2: Organizations
    cna: CVECNAForm
    adps: CVEADPForm[]

    // Step 3: References
    references: CVEReferenceForm[]

    // Step 4: Problem Types
    problemTypes: CVEProblemTypeForm[]

    // Step 5: Metrics
    metrics: CVEMetricForm[]

    // Step 6: Affected Products
    affected: CVEAffectedForm[]

    // Step 7: Descriptions
    descriptions: CVEDescriptionForm[]

    // Step 8: Aliases (simple string identifiers, not relations)
    aliases: string[]
}

/**
 * CVE Form History item for localStorage
 */
export interface CVEFormHistory {
    timestamp: number
    cveId: string
    source: string
    json: string // Serialized CVE 5.0 JSON
    formData: CVEFormData // For editing/viewing
}

/**
 * CVE 5.0 JSON Schema validation result
 */
export interface CVEValidationResult {
    valid: boolean
    errors: string[]
}

/**
 * CVE Upload API response
 */
export interface CVEUploadResponse {
    success: boolean
    cveId?: string
    source?: string
    createdRecords?: {
        metadata: boolean
        cna: boolean
        adps: number
        references: number
        problemTypes: number
        metrics: number
        affected: number
        descriptions: number
    }
    error?: string
    validationErrors?: string[]
}

// VDB Patch Intelligence Interface
export interface PatchIntelligence {
    hasPatch: boolean
    ecosystem?: string
    packageName?: string
    packageVersion?: string
    commitHash?: string
    versionStatement?: string
    remediationAdvice?: string
    cweRemediations?: string[]
    pixAnalysis?: string
    affectedFunctions?: string[]
    sources: string[]
}

// GitHub PR Enrichment for CVE References
export interface GitHubPREnrichment {
    diff_url: string | null
    state: string | null
    title: string | null
    author: string | null
    labels: string[]
    merged_at: number | null
    merge_commit_sha: string | null
    health: {
        comments: number
        review_comments: number
        commits: number
        additions: number
        deletions: number
        changed_files: number
    } | null
}

// GitHub Commit Enrichment for CVE References
export interface GitHubCommitEnrichment {
    author_email: string | null
    author_login: string | null
    verified: boolean
    createdAt: number | null
    message: string | null
    commit_health: {
        additions: number
        deletions: number
        total: number
        comment_count: number
        files_changed: number
    } | null
}

// GitHub Gist Enrichment for CVE References
export interface GitHubGistEnrichment {
    gist_id: string
    title: string | null // From description property
    owner_login: string | null // From owner.login
    createdAt: number | null // From created_at
    updatedAt: number | null // From updated_at
    public: boolean
    files_count: number
    files: string[] // Array of filenames
    comments_count: number
}

// ExploitDB Enrichment for CVE References
export interface ExploitDBEnrichment {
    exploitId: string
    title: string | null
    author: string | null
    date: number | null // Unix timestamp
    platform: string | null
    type: string | null
    port: number | null
    verified: boolean
}

// VulnerabilityLab Enrichment for CVE References
export interface VulnerabilityLabEnrichment {
    vlId: string
    title: string | null
    createdAt: number | null // Release date or earliest timeline date
    updatedAt: number | null // Latest disclosure/patch date
    exploitationTechnique: string | null // Remote, Local, etc.
    authenticationType: string | null // Auth requirements
    userInteraction: string | null // User interaction level
    author: string | null // Credits & Authors
}
