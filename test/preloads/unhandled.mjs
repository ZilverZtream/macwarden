import { afterHandlerInstalled } from './wait-for-handler.mjs';

afterHandlerInstalled('unhandledRejection', () => {
  void Promise.reject(new Error(process.env.MACWARDEN_CRASH_MARKER));
});
