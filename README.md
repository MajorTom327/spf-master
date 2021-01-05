# SPF Master

Spf Master is a basic librairie to inspect domain information.
It should inspect domain with somes recursion to try to find the requested informations.

You can search for `includes`, `ip` or `domain` in the records.

The limitation of the recursion and this setting add the possibility to look through many includes in somes cases.

I just review the lib to extend and make it easy to integrate through JS and TS.
And to make the usage of the lib thread safe 🎉

### Usage:
```typescript
import Inspector from 'spf-master';

// * Elements to fins (All are optionals)
const options = {
  ips: [],
  domains: [],
  includes: [],
  maxDepth: 3
}

// * If we found all our elements before reach the max depth
// * Stop the recursion
const stopOnMatch = true;

// * Inspect the domain and
Inspector('domain.tld', options, stopOnMatch)
.then((report) => {
  // * The report of all informations found,
  // * The query which match
  // * Etc...
  console.log(report);
});
```

### Issues

Please, if you find any issue, feel free to open an issue on [the repository on Github](https://github.com/MajorTom327/spf-master)