import * as dns from 'dns';
import SpfParser from 'spf-parse';
import { Record, SpfMechanism, SpfType } from './Record'
import { v4 as ipV4, v6 as ipV6 } from 'ip-regex'
import { Report } from './Report';
import { InspecterError } from './Inspecter';

const R = require('ramda');

type Search = {
  ips: string[]
  includes: string[],
  domains: string[],
}

type Status = {
  found: boolean,
  match: boolean
} & Search


const isRawIp = (domain: string): boolean => ipV4().test(domain) || ipV6().test(domain);

const SpfInspector = (domain: string, search: Partial<Search> & { maxDepth?: number } = {}, stopOnMatch: boolean = true): Promise<Report> => {
  let status: Status = {
    found: false,
    ips: [],
    includes: [],
    domains: [],
    match: false
  }

  const getDnsRecord = (domain: string): Promise<Record[]> => {
    if (isRawIp(domain)) return Promise.reject(new Error(`Domain ${domain} is a raw ip !`));
    return new Promise<Record[]>((resolve, reject) => {
      dns.resolveTxt(domain, (err, entries) => {
        if (err) return reject(err);

        resolve(
          entries
            .reduce((accumulator, currentValue) => [...accumulator, ...currentValue])
            .filter((record: string): boolean => record.includes('v=spf1')) // * Hide not SPF entries
            .map(// * Transorm to data record
              (record: string): Record => ({
                record,
                detail: SpfParser(record || ''),
              }),
            ),
        )
      });
    })
  }

  const updateState = (record: Record): void => {
    const mechanisms = R.pathOr([], ['detail', 'mechanisms'], record);

    if (R.length(mechanisms) === 0) return;

    // * Update ips
    mechanisms
      .filter(R.or(R.propEq('type', SpfType.ip4), R.propEq('type', SpfType.ip6)))
      .map((R.prop('value')))
      .forEach((ip) => {
        if (R.contains(ip, status.ips)) return;
        // * Mutate the state
        status.ips.push(ip);
      })

    // * Update includes
    mechanisms
      .filter(R.propEq('type', SpfType.include))
      .map((R.prop('value')))
      .forEach((include) => {
        if (R.contains(include, status.includes)) return;
        // * Mutate the state
        status.includes.push(include);
      })

    // * Update domain
    mechanisms
      .filter(R.propEq('type', SpfType.a))
      .map((R.prop('value')))
      .forEach((domain) => {
        if (R.contains(domain, status.domains)) return;
        // * Mutate the state
        status.domains.push(domain);
      })

    // * Check if it's a full match
    status.match = [
      R.equals(status.includes, R.propOr([], 'includes', search)),
      R.equals(status.ips, R.propOr([], 'ips', search)),
      R.equals(status.domains, R.propOr([], 'domains', search)),
    ].every(R.equals(true)) || status.match
  }

  const getIncludes = async (record: Record, depth: number) => {
    updateState(record);

    if (status.match && stopOnMatch) return Promise.resolve(record);
    if (depth < 0) return Promise.resolve(record);

    // * Get next includes to parse
    const includes: SpfMechanism[] = R.pathOr([], ['detail', 'mechanisms'], record)
      .filter(R.propEq('type', SpfType.include));

    // * We are a the lowest level
    if (R.length(includes) === 0) return Promise.resolve(record);

    const recordsFromIncludes: Record[][] = await Promise.all(
      includes
        .map((include: SpfMechanism): string => include.value) // * Map values
        .map((include: string): Promise<Record[]> => getDnsRecord(include)), // * Get the record
    )

    // * Recursion call to get sub-includes
    record.includes = await Promise.all(
      R.flatten(recordsFromIncludes)
        .map((el) => new Promise<Record>(async (resolve) => resolve(await getIncludes(el, depth - 1))))
    )

    // * Recursion should be done
    return Promise.resolve(record);
  }

  return getDnsRecord(domain)
    .then((records) => {

      // * Get recursive includes with depth control
      return Promise.all(
        records
          .map((record: Record): Promise<Record> => {
            if (R.path(['detail', 'valid'], record)) return getIncludes(record, Math.max(0, R.defaultTo(10, search.maxDepth)));
            return Promise.resolve(record);
          })
      ).then((records: Record[]) => {
        // * Here we got the finals records.
        // * Format the report

        const helperRemoveEmpty = R.compose(
          R.reject(
            R.either(R.isNil, R.isEmpty)
          ),
          R.defaultTo([])
        )
        return Promise.resolve({
          records: records || [],
          found: {
            ips: helperRemoveEmpty(status.ips),
            includes: helperRemoveEmpty(status.includes),
            domains: helperRemoveEmpty(status.domains),
          },
          isMatch: status.match,
          reason: '',
        })
      }).catch((err) => {
        return Promise.reject({
          records: [],
          found: {
            ips: [],
            includes: [],
            domains: []
          },
          isMatch: false,
          reason: InspecterError.NOTFOUND
        })
      })
    });
}

export default SpfInspector
