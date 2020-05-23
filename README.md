# SPF-Master

## Overview

SPF-Master is a simple inspector SPF DNS record.

It's a basic surcharge of DNS module but including recursion and details informations.

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

The current limitation is not thread save.
You should create a new inspecter with sames settings for running side-by-side.

You can re-use instance. But starting a new inspect on same instance until the last inspection finished will break.
