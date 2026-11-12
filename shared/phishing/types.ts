/**
 * Wire types for the Phishing Investigation pipeline, shared by the Worker (producer) and the React app (consumer).
 *
 * Every stage emits the same two things so the verdict engine can combine them without knowing who produced them:
 *  - Finding:     one observation, with enough context to weigh it (severity, exactness, reliability, trust).
 *  - CheckResult: one visible line in the "check status" table. A failed or skipped check must never look clean.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** The five dimensions the verdict engine weighs. */
export type Dimension = 'authentication' | 'infrastructure' | 'url' | 'attachment' | 'content';

/**
 * How much the evidence can be believed.
 *  receiver_reported:       written by the receiving mail system (as supplied: pasted headers can still be edited).
 *  unverified:              supplied by the user or by a header that cannot be tied to the receiver.
 *  independently_verified:  reproduced by Spectrix itself (e.g. a DNS lookup of the published SPF record).
 *  derived:                 computed from other evidence (e.g. a mismatch between two headers).
 */
export type TrustLevel = 'receiver_reported' | 'unverified' | 'independently_verified' | 'derived';

/** Does the observation concern the actual sender / URL / file, or only something related to it? */
export type Exactness = 'exact' | 'related' | 'contextual';
export type Reliability = 'high' | 'medium' | 'low';

export type IndicatorType = 'email' | 'domain' | 'ip' | 'url' | 'hash' | 'filename';

export interface Finding {
  /** Stable rule id (e.g. "reply_to_mismatch"): the verdict engine maps ids to points and verdict rules. */
  id: string;
  dimension: Dimension;
  severity: Severity;
  title: string;
  detail: string;
  /** Who said it: "header-forensics", "VirusTotal", "OpenPhish" ... */
  source: string;
  exactness: Exactness;
  reliability: Reliability;
  trust: TrustLevel;
  /** Short quoted evidence lines (header values, matched text). */
  evidence?: string[];
  indicator?: { type: IndicatorType; value: string };
  observedAt?: string | null;
}

export type CheckStatus = 'complete' | 'failed' | 'skipped' | 'not_applicable';
export type Stage = 'parse' | 'headers' | 'authentication' | 'sender' | 'urls' | 'attachments' | 'content' | 'verdict';

export interface CheckResult {
  id: string;
  stage: Stage;
  label: string;
  status: CheckStatus;
  /** Short outcome ("pass", "4 detections", "no record") or null when the check did not produce one. */
  result: string | null;
  detail?: string;
  ms?: number;
}

/* ------------------------------------------------------------------ input */

export interface SuppliedSender {
  email?: string;
  displayName?: string;
  /** "Sender domain / claimed organization website": what the sender CLAIMS to be, not necessarily where mail came from. */
  domain?: string;
  /** Unverified clue: the headers decide which IP is actually investigated. */
  ip?: string;
}

export interface SuppliedAttachment { name?: string; hash?: string }

export interface PhishingInput {
  /** Raw message headers. A full pasted .eml (headers, blank line, body) is also accepted. */
  headers?: string;
  subject?: string;
  body?: string;
  sender?: SuppliedSender;
  urls?: string[];
  attachments?: SuppliedAttachment[];
}

export const LIMITS = {
  /** Whole request body. Embedded base64 attachments are what make this large. */
  requestBytes: 3_000_000,
  headerBytes: 100_000,
  bodyChars: 2_000_000,
  /** Plain text kept for content analysis. */
  textChars: 200_000,
  field: 512,
  urls: 50,
  attachments: 20,
  links: 200,
  mimeParts: 120,
  mimeDepth: 6,
} as const;

/* ------------------------------------------------------------- indicators */

/** sender_client: the device that sent an internal Microsoft 365 message (recorded by Exchange). */
export type IpRole = 'connecting' | 'claimed_origin' | 'x_originating' | 'supplied' | 'sender_client';
export interface IpIndicator { ip: string; role: IpRole; trust: TrustLevel; hop: number | null; note?: string }

export type DomainRole = 'from' | 'return_path' | 'reply_to' | 'sender_header' | 'dkim' | 'spf' | 'message_id' | 'claimed_org' | 'supplied';
export interface DomainIndicator { domain: string; roles: DomainRole[] }

export type EmailRole = 'from' | 'return_path' | 'reply_to' | 'sender_header' | 'supplied';
export interface EmailIndicator { address: string; roles: EmailRole[] }

export type HashType = 'md5' | 'sha1' | 'sha256';
export interface AttachmentRef {
  filename: string | null;
  hash: string | null;
  hashType: HashType | null;
  size: number | null;
  /** "embedded": found in the pasted message; "supplied": typed in by the user. */
  origin: 'embedded' | 'supplied';
  declaredType: string | null;
}

export interface IndicatorSet {
  emails: EmailIndicator[];
  domains: DomainIndicator[];
  ips: IpIndicator[];
  /** Normalised (credential-free) URLs worth investigating, in extraction order. */
  urls: string[];
  attachments: AttachmentRef[];
}
