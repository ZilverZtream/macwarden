import { afterHandlerInstalled } from './wait-for-handler.mjs';

afterHandlerInstalled('uncaughtException', () => {
  throw new Error(process.env.MACWARDEN_CRASH_MARKER);
});
