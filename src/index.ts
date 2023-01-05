import express, { Application, Request, Response } from 'express';
import { createHmac, Hmac } from 'crypto';
import dotenv from 'dotenv';
import { Docker } from 'node-docker-api';
import type { Service } from 'node-docker-api/lib/service';

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

const docker: Docker = new Docker({ socketPath: '/var/run/docker.sock' });
docker.info().then((info: any): void => {
  // eslint-disable-next-line no-console
  console.info(`connected to docker daemon running on ${info.Name}`);
});

const app: Application = express();
app.use(express.json({}));

app.post('/', (req: Request, res: Response): void => {
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
  envs.forEach((packageUrl: string, id: string): void => {
    if (reqPackageUrl === packageUrl) {
      const service: Service = docker.service.get(id);
      // eslint-disable-next-line no-console
      console.info(`received valid webhook. updating service ${id} with image ${packageUrl}`);
      service.update()
        .then((): void => {
          res.status(200).send('OK');
        })
        .catch((): void => {
          res.status(500).send('ERROR_UPDATING_SERVICE');
        });
    } else {
      res.status(400).send('INVALID_SERVICE');
    }
  });
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
