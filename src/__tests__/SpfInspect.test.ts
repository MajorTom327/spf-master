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

// * Test with ips error
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
