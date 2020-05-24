# SPF-Master ![npm](https://img.shields.io/npm/v/spf-master) ![NPM](https://img.shields.io/npm/l/spf-master)

Simple SPF Record Recursive inspector

## Overview

spf-master is a inspector of the DNS record for getting info on the Mail sending status of a domain.
You can use it to check if you can send a mail with this domain from the server with the ip.

This Libraries is a simple surcharge of the DNS node module. It use spf-parse for matching the DNS record and do recursive inspection on the domain if needed.

## Use case

The most simple usage it's to check if a customer of your service has set correctly his domains records for making you able to send mail from his domain without getting flagged as Spam

## Usage

### Typescript

```typescript
import { SpfInspector } from 'spf-master';

const Options: Partial<InspecterOptions> = {
  depth: 3, // Max depth limitation (default: 3)
  stopOnMatch: true, // Stop when all search options have matched (default: true)
};

const inspector: SpfInspector = new SpfInspector(options);

inspector
  .inspect('domain.tld', {
    ips: [], // * Ips to find
    includes: [], // * Includes to find
    domains: [], // * Domains to find
  })
  .then((result: InspecterResults) => {
    console.log(result);
  });
```

## Limitations

The current version isn't thread save. One instance of the checker should be waited to finish a check before starting an other check.

Re-using an instance is technically possible. But if you start another check while the last check isn't finished, the status of the precedent check can be unexpected.
