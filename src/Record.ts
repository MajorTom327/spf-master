export enum SpfType {
  include = 'include',
  version = 'version',
  all = 'all',
  mx = 'mx',
  ip4 = 'ip4',
  ip6 = 'ip6',
  a = 'a',
}

export interface SpfMechanism {
  prefix: string;
  type: SpfType;
  prefixdesc?: string;
  description: string;
  value: string;
}

export interface SpfRecord {
  mechanisms: SpfMechanism[];
  valid: boolean;
}

export interface Record {
  record: string;
  detail: SpfRecord;
  includes?: Record[];
}

export default Record;