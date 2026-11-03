import { ok, route } from '../_lib/respond';

export const onRequestGet = route(async () => ok({ status: 'ok', service: 'spectrix-api', version: '1.0.0' }));
