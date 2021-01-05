import Record from './Record';

export type Report = {
  records: Record[],
  found: {
    ips: string[],
    includes: string[],
    domains: string[]
  },
  isMatch: boolean,
  reason: string
}

export default Report;