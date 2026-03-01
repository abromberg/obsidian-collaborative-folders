import type { FolderInviteRecord, FolderMemberRecord } from '@obsidian-teams/shared'

/** True when folder is still shared with others or has pending invitations. */
export function hasPendingOrActiveShares(
  members: FolderMemberRecord[],
  invites: FolderInviteRecord[]
): boolean {
  const hasActiveMemberShares = members.some((member) => member.role !== 'owner')
  if (hasActiveMemberShares) return true
  return invites.some((invite) => invite.status === 'active')
}
