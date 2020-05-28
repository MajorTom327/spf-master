import { Inspector } from './SpfInspect';

export { Inspector as SpfInspector } from './SpfInspect';

() => {
  const inspector = new Inspector({});
  inspector.inspect('google.com', {}).then((result) => {
    console.log(result);
  });
};
