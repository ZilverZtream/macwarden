import { afterHandlerInstalled } from './wait-for-handler.mjs';

afterHandlerInstalled('warning', () => {
  process.emitWarning(new Error(process.env.MACWARDEN_CRASH_MARKER));
});
