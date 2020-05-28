import * as dns from 'dns';
import * as SpfParser from 'spf-parse';
import { InspecterSearch, InspecterResults, InspecterOptions, InspecterError } from './types/Inspecter';
import { Record, SpfMechanism, SpfType } from './types/Record';

// Todo: Match IPv6
export const isRawIP = (str: string): boolean => {
  return /(?:[0-9]{1,3}\.){3}[0-9]{1,3}/.test(str);
};

const CrossMatch = (lrs: string[], rhs: string[]): boolean => {
  return rhs.reduce((red: boolean, el: string) => lrs.includes(el), true);
};

export class Inspector {
  options: InspecterOptions;

  ipsToFind: string[] = [];
  includesToFind: string[] = [];
  domainsToFind: string[] = [];

  ipsRecord: string[] = [];
  includeRecord: string[] = [];
  domainRecord: string[] = [];

  ipsFound: string[] = [];
  includesFound: string[] = [];
  domainsFound: string[] = [];

  match: boolean = false;
  reason?: InspecterError[];

  constructor(options: Partial<InspecterOptions>) {
    this.options = {
      depth: options.depth || 3,
      stopOnMatch: options.stopOnMatch !== undefined ? options.stopOnMatch : true,
    };
  }

  inspect(domain: string, search: Partial<InspecterSearch>): Promise<InspecterResults> {
    if (search.ips) this.ipsToFind = search.ips;
    if (search.domains) this.domainsToFind = search.domains;
    if (search.includes) this.includesToFind = search.includes;

    // * Reset state
    this.match = false;
    this.ipsFound = [];
    this.includesFound = [];
    this.domainsFound = [];

    return new Promise((resolve, reject) => {
      this.getDnsRecord(domain)
        .then((records: Record[]) => {
          Promise.all(
            records.map(
              (record: Record): Promise<Record> => {
                if (record.detail.valid) return this.getIncludes(record, this.options.depth);
                return Promise.resolve(record);
              },
            ),
          )
            .then((recordsList: Record[]) => {
              resolve({
                records: recordsList || [],
                found: {
                  ips: this.ipsFound || [],
                  includes: this.includesFound || [],
                  domains: this.domainsFound || [],
                },
                isMatch: this.match,
                reason: this.reason,
              });
            })
            .catch(reject);
        })
        .catch((data) => {
          const error: InspecterResults = {
            records: [],
            isMatch: false,
            found: {
              ips: [],
              includes: [],
              domains: [],
            },
            reason: ['ENODATA' ? InspecterError.NOTFOUND : InspecterError.UNKNWON],
          };
          reject(error);
        });
    });
  }

  getDnsRecord(domain: string): Promise<Record[]> {
    if (isRawIP(domain)) return Promise.reject(new Error(`Hostname "${domain}" is a raw IP`));
    return new Promise<Record[]>((resolve, reject) => {
      dns.resolveTxt(domain, (err: Error | null, entries: string[][]) => {
        if (err) {
          reject(err);
          return;
        }

        if (entries.length === 0) {
          resolve([]);
          return;
        }
        resolve(
          entries[0]
            .filter((record: string): boolean => record.includes('v=spf1'))
            .map(
              (record: string): Record => ({
                record,
                detail: SpfParser(record || ''),
              }),
            ),
        );
      });
    });
  }

  async getIncludes(record: Record, depth: number): Promise<Record> {
    // Update records info

    this.updateRecordsMatch(record);

    // * If it's a match and option set Stop on first match
    if (this.match && this.options.stopOnMatch) return Promise.resolve(record);
    if (depth <= 0) return Promise.resolve(record);

    // * Get all includes to search deeper
    const includes: SpfMechanism[] = (record.detail.mechanisms || []).filter((r) => r.type === SpfType.include);
    if (includes.length === 0) return Promise.resolve(record);

    const recordsFromIncludes: Record[][] = await Promise.all(
      includes
        .map((include: SpfMechanism): string => include.value)
        .map((include: string): Promise<Record[]> => this.getDnsRecord(include)),
    );

    // * Apply records to current record and recurse
    record.includes = await Promise.all(
      recordsFromIncludes
        .reduce((red: Record[], records: Record[]): Record[] => [...red, ...records])
        .map((el) => {
          return new Promise<Record>(async (resolve) => {
            resolve(await this.getIncludes(el, depth - 1));
          });
        }),
    );

    // * Recursion should be done
    return Promise.resolve(record);
  }

  updateRecordsMatch(record: Record): void {
    const mechanisms: SpfMechanism[] = record.detail.mechanisms || [];

    if (mechanisms.length === 0) return;
    const includes: string[] = mechanisms
      .filter((m: SpfMechanism): boolean => m.type === SpfType.include)
      .map((m: SpfMechanism): string => m.value);

    const ips: string[] = mechanisms
      .filter((m: SpfMechanism): boolean => [SpfType.ip4, SpfType.ip6].includes(m.type))
      .map((m: SpfMechanism): string => m.value);

    const domain: string[] = mechanisms
      .filter((m: SpfMechanism): boolean => m.type === SpfType.a)
      .map((m: SpfMechanism): string => m.value);

    this.includesFound = [...this.includesFound, ...includes];
    this.ipsFound = [...this.ipsFound, ...ips];
    this.domainsFound = [...this.domainsFound, ...ips];

    // * Check if it's a full match
    const statesCheck: boolean[] = [
      CrossMatch(this.includesFound, this.includesToFind),
      CrossMatch(this.ipsFound, this.ipsToFind),
      CrossMatch(this.domainsFound, this.domainsToFind),
    ];
    this.match = statesCheck.every((e) => e === true);

    if (!this.match) {
      let err: InspecterError[] = [];
      err = !statesCheck[0] ? [...err, InspecterError.INC_NOT_MATCH] : err;
      err = !statesCheck[1] ? [...err, InspecterError.IPS_NOT_MATCH] : err;
      err = !statesCheck[2] ? [...err, InspecterError.DOM_NOT_MATCH] : err;
      this.reason = [...err];
    } else {
      this.reason = undefined;
    }
  }
}
