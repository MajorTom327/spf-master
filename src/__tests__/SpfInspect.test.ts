import { SpfInspector } from '../index';
import { InspecterError, InspecterResults } from '../types/Inspecter';

test('Basic domain', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter.inspect('google.com', {}).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeUndefined();
      expect(record.isMatch).toBeTruthy();
      const r = record.records[0];

      expect(r.record).toContain('v=spf1');
      expect(r.record).toBe('v=spf1 include:_spf.google.com ~all');
      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Basic domain with include', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter.inspect('google.com', { includes: ['_spf.google.com'] }).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeUndefined();
      expect(record.isMatch).toBeTruthy();
      expect(record.found.ips.length).toBe(0);
      expect(record.found.includes.length).toBe(1);
      expect(record.found.domains.length).toBe(0);
      expect(record.found.includes).toContain('_spf.google.com');
      const r = record.records[0];

      expect(r.record).toContain('v=spf1');
      expect(r.record).toBe('v=spf1 include:_spf.google.com ~all');
      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Basic domain with depth', (done) => {
  const inspecter: SpfInspector = new SpfInspector({ depth: 1, stopOnMatch: false });
  try {
    inspecter.inspect('google.com', {}).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeUndefined();
      expect(record.isMatch).toBeTruthy();

      expect(record.found.ips.length).toBe(0);
      expect(record.found.includes.length).toBe(4);
      expect(record.found.domains.length).toBe(0);

      expect(record.found.includes).toContain('_spf.google.com');
      expect(record.found.includes).toContain('_netblocks.google.com');
      expect(record.found.includes).toContain('_netblocks2.google.com');
      expect(record.found.includes).toContain('_netblocks3.google.com');

      const r = record.records[0];

      expect(r.record).toContain('v=spf1');
      expect(r.record).toBe('v=spf1 include:_spf.google.com ~all');
      expect(r.includes).toBeDefined();
      expect(r.includes?.length).toBe(1);
      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Basic domain with depth and stop on match', (done) => {
  const inspecter: SpfInspector = new SpfInspector({ depth: 1, stopOnMatch: true });
  try {
    inspecter.inspect('google.com', {}).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeUndefined();
      expect(record.isMatch).toBeTruthy();

      const r = record.records[0];

      expect(r.record).toContain('v=spf1');
      expect(r.record).toBe('v=spf1 include:_spf.google.com ~all');
      expect(r.includes).toBeUndefined();
      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Error with ips', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter.inspect('google.com', { ips: ['127.0.0.1'] }).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeDefined();
      expect(record.isMatch).toBeFalsy();
      expect(record.reason).toContain(InspecterError.IPS_NOT_MATCH);

      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Error with includes', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter.inspect('google.com', { includes: ['koink.com'] }).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeDefined();
      expect(record.isMatch).toBeFalsy();
      expect(record.reason).toContain(InspecterError.INC_NOT_MATCH);

      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Error with domain', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter.inspect('google.com', { domains: ['domain.com'] }).then((record: InspecterResults) => {
      expect(record.records.length).toBe(1);
      expect(record.reason).toBeDefined();
      expect(record.isMatch).toBeFalsy();
      expect(record.reason).toContain(InspecterError.DOM_NOT_MATCH);

      done();
    });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Error with all', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    inspecter
      .inspect('google.com', { ips: ['127.0.0.1'], includes: ['koink.com'], domains: ['domain.com'] })
      .then((record: InspecterResults) => {
        expect(record.records.length).toBe(1);
        expect(record.reason).toBeDefined();
        expect(record.isMatch).toBeFalsy();
        expect(record.reason).toContain(InspecterError.IPS_NOT_MATCH);
        expect(record.reason).toContain(InspecterError.INC_NOT_MATCH);
        expect(record.reason).toContain(InspecterError.DOM_NOT_MATCH);

        done();
      });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});

test('Domain not found', (done) => {
  const inspecter: SpfInspector = new SpfInspector({});
  try {
    const domain: string = `84awe9f8awe4f84q231f5e4dg18sxd4sg96w87r4fazdfb98s7r4gaw8e4faedr48bsd8rh.com`;
    inspecter
      .inspect(domain, {})
      .then((record) => {
        done('Should fail to find domain');
      })
      .catch((data: InspecterResults) => {
        expect(data.records.length).toBe(0);
        expect(data.isMatch).toBeFalsy();
        expect(data.reason).toBeDefined();
        expect(data.reason?.length).toBe(1);
        expect(data.reason).toContain(InspecterError.NOTFOUND);
        done();
      });
  } catch (error) {
    done(error);
  }
  expect('test').toBe('test');
});
