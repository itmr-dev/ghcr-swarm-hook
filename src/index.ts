import express, { Application, Request, Response } from 'express';
import { createHmac, Hmac } from 'crypto';
import dotenv from 'dotenv';
import Docker, { Service } from 'dockerode';

dotenv.config();

if (!process.env.SECRET) {
  throw new Error('SECRET not set');
}

enum LOG_STATUS { VERBOSE = 'VERBOSE', INFO = 'INFO', WARN = 'WARN', ERROR = 'ERROR' }
function log(message: string, status: LOG_STATUS = LOG_STATUS.INFO): void {
  switch (status) {
    case LOG_STATUS.VERBOSE:
      if (process.env.LOG_LEVEL === 'VERBOSE') {
        // eslint-disable-next-line no-console
        console.log(message);
      }
      break;
    case LOG_STATUS.INFO:
      // eslint-disable-next-line no-console
      console.info(message);
      break;
    case LOG_STATUS.WARN:
      // eslint-disable-next-line no-console
      console.warn(message);
      break;
    case LOG_STATUS.ERROR:
      // eslint-disable-next-line no-console
      console.error(message);
      break;
    default:
      break;
  }
}

const envs: Map<string, string> = new Map<string, string>();

Object.keys(process.env).forEach((env: string): void => {
  if (env.startsWith('SER_')) {
    envs.set(env.slice(4), process.env[env] as string);
    log(`found service ${env.slice(4)} with image ${process.env[env]}`, LOG_STATUS.VERBOSE);
  }
});
log(`found ${envs.size} services to update`, LOG_STATUS.VERBOSE);

const docker: Docker = new Docker({ socketPath: '/var/run/docker.sock' });
docker.info().then((info: any): void => {
  log(`connected to docker daemon running on ${info.Name}`);
});

const app: Application = express();
app.use(express.json({}));

app.post('/', async (req: Request, res: Response): Promise<void> => {
  log(`received webhook with action ${req.body.action}`, LOG_STATUS.VERBOSE);
  if (req.body.action !== 'published') {
    res.status(400).send('IGNORING_INVALID_ACTION');
    log(`ignoring invalid action ${req.body.action}`, LOG_STATUS.VERBOSE);
    return;
  }
  const reqPackageUrl: string = req.body.package.package_version.package_url;
  if (!reqPackageUrl) {
    res.status(400).send('INVALID_PAYLOAD_MISSING_PACKAGE_URL');
    log('ignoring invalid payload, missing package_url', LOG_STATUS.VERBOSE);
    return;
  }
  const hmac: Hmac = createHmac('sha256', process.env.SECRET as string);
  const signature: string = `sha256=${hmac.update(JSON.stringify(req.body)).digest('hex')}`;
  if (req.headers['x-hub-signature-256'] !== signature) {
    res.status(400).send('INVALID_SIGNATURE');
    log('ignoring invalid signature', LOG_STATUS.VERBOSE);
    return;
  }
  const services: Array<string> = [];
  // eslint-disable-next-line no-restricted-syntax
  for await (const element of envs) {
    if (reqPackageUrl === element[1]) {
      log(`received valid webhook. updating service ${element[0]} with image ${element[1]}`);
      services.push(element[0]);
    }
  }
  if (services.length === 0) {
    log(`invalid webhook. no service found for package ${reqPackageUrl}`);
    res.status(400).send('NO_SERVICE_FOUND_FOR_PACKAGE_URL');
    return;
  }
  log(`updating ${services.length} services`, LOG_STATUS.VERBOSE);
  // eslint-disable-next-line no-restricted-syntax
  for await (const id of services) {
    const service: Service = docker.getService(id);
    log(`updating service ${id}`, LOG_STATUS.VERBOSE);
    try {
      service.inspect()
        .then((inspected: any): void => {
          log(`inspected service ${id}`, LOG_STATUS.VERBOSE);
          service.update({
            ...inspected.Spec,
            version: inspected.Version.Index,
            TaskTemplate: {
              ContainerSpec: {
                Image: reqPackageUrl,
              },
            },
          });
          log(`updated service ${id}`, LOG_STATUS.VERBOSE);
        });
    } catch (error) {
      log(`ERROR_UPDATING_SERVICE ${error}`, LOG_STATUS.ERROR);
      res.status(500).send('ERROR_UPDATING_SERVICE');
      return;
    }
  }
  res.status(200).send('OK');
  log(`done handling webhook for package ${reqPackageUrl}`);
});

app.listen(process.env.PORT || 3000, (): void => {
  log(`ready to receive webhooks on port ${process.env.PORT || 3000}`);
});

function exit(signal: string): void {
  log(`received shutdown signal (${signal}), exiting`);
  process.exit(0);
}
process.on('SIGINT', (): void => exit('SIGINT'));
process.on('SIGTERM', (): void => exit('SIGTERM'));
