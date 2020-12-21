import SpfInspector from './SpfInspector';

(async () => {

  const result = await SpfInspector('google.com', { ips: ['127.0.0.1'] }, false);

  console.log(JSON.stringify(result, null, 4))
})()