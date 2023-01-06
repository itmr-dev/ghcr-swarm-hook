import express, { Application, Request, Response } from 'express';
import { createHmac, Hmac } from 'crypto';
import dotenv from 'dotenv';
import Docker, { Service } from 'dockerode';

dotenv.config();

if (!process.env.SECRET) {
  throw new Error('SECRET not set');
}

const envs: Map<string, string> = new Map<string, string>();

Object.keys(process.env).forEach((env: string): void => {
  if (env.startsWith('SER_')) {
    envs.set(env.slice(4), process.env[env] as string);
  }
});
console.log(envs);

const docker: Docker = new Docker({ socketPath: '/var/run/docker.sock' });
docker.info().then((info: any): void => {
  // eslint-disable-next-line no-console
  console.info(`connected to docker daemon running on ${info.Name}`);
});

const app: Application = express();
app.use(express.json({}));

app.post('/', async (req: Request, res: Response): Promise<void> => {
  if (req.body.action !== 'published') {
    res.status(400).send('IGNORING_INVALID_ACTION');
    return;
  }
  const reqPackageUrl: string = req.body.package.package_version.package_url;
  if (!reqPackageUrl) {
    res.status(400).send('INVALID_PAYLOAD_MISSING_PACKAGE_URL');
    return;
  }
  const hmac: Hmac = createHmac('sha256', process.env.SECRET as string);
  const signature: string = `sha256=${hmac.update(JSON.stringify(req.body)).digest('hex')}`;
  if (req.headers['x-hub-signature-256'] !== signature) {
    res.status(400).send('INVALID_SIGNATURE');
    return;
  }
  const services: Array<string> = [];
  console.log(reqPackageUrl);
  // eslint-disable-next-line no-restricted-syntax
  for await (const element of envs) {
    console.log(element[1], element[0]);
    if (reqPackageUrl === element[1]) {
      // eslint-disable-next-line no-console
      console.info(`received valid webhook. updating service ${element[0]} with image ${element[1]}`);
      services.push(element[0]);
    }
  }
  if (services.length === 0) {
    res.status(400).send('NO_SERVICE_FOUND_FOR_PACKAGE_URL');
    return;
  }
  // eslint-disable-next-line no-restricted-syntax
  for await (const id of services) {
    const service: Service = docker.getService(id);
    console.log(service);
    try {
      service.inspect()
        .then((inspected: any): void => {
          console.log(inspected);
          service.update({
            ...inspected.Spec,
            version: inspected.Version.Index,
            TaskTemplate: {
              ContainerSpec: {
                Image: reqPackageUrl,
              },
            },
          });
        });
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn('ERROR_UPDATING_SERVICE');
      console.log(error);
      res.status(500).send('ERROR_UPDATING_SERVICE');
      return;
    }
  }
  res.status(200).send('OK');
});

app.listen(process.env.PORT || 3000, (): void => {
  // eslint-disable-next-line no-console
  console.info(`ready to receive webhooks on port ${process.env.PORT || 3000}`);
});

function exit(signal: string): void {
  // eslint-disable-next-line no-console
  console.info(`received shutdown signal (${signal}), exiting`);
  process.exit(0);
}
process.on('SIGINT', (): void => exit('SIGINT'));
process.on('SIGTERM', (): void => exit('SIGTERM'));
