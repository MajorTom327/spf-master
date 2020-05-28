import { Record } from './Record';

export interface InspecterSearch {
  ips: string[];
  includes: string[];
  domains: string[];
}

export interface InspecterOptions {
  stopOnMatch: boolean;
  depth: number;
}

export interface InspecterResults {
  records: Record[];
  found: {
    ips: string[];
    includes: string[];
    domains: string[];
  };
  isMatch: boolean;
  reason?: InspecterError[];
}

export enum InspecterError {
  UNKNWON = 'EUNKNWON',
  NOTFOUND = 'ENOTFOUND',
  IPS_NOT_MATCH = 'IPSMATCH',
  INC_NOT_MATCH = 'INCMATCH',
  DOM_NOT_MATCH = 'DOMMATCH',
}
