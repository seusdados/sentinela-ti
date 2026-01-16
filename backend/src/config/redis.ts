import { Redis } from 'ioredis';
import { env } from './env';

export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
});

redis.on('error', (err) => {
  console.error('❌ Erro de conexão Redis:', err.message);
});

redis.on('connect', () => {
  console.log('✅ Redis conectado');
});
