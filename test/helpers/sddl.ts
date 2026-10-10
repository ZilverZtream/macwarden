// How Windows writes an account as an ACE trustee in SDDL. The local machine's built-in
// Administrator (RID 500) and Guest (RID 501) accounts are written as the aliases LA and LG
// rather than as their SIDs; GitHub's Windows runners run as the built-in Administrator.
// Every other account is written as its SID.
export function sddlTrustee(sid: string): string {
  const local = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(sid);
  if (local?.[1] === '500') return 'LA';
  if (local?.[1] === '501') return 'LG';
  return sid;
}
