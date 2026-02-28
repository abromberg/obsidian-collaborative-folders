import test from 'node:test'
import assert from 'node:assert/strict'
import type { FolderInviteRecord, FolderMemberRecord, FolderInviteStatus } from '@obsidian-teams/shared'
import { hasPendingOrActiveShares } from '../ui/share-state'

function member(role: FolderMemberRecord['role']): FolderMemberRecord {
  return {
    clientId: role === 'owner' ? 'owner-1' : 'editor-1',
    displayName: role === 'owner' ? 'Owner' : 'Editor',
    inviteeLabel: null,
    role,
    tokenVersion: 1,
    joinedAt: '2026-02-27T00:00:00.000Z',
  }
}

function invite(status: FolderInviteStatus): FolderInviteRecord {
  return {
    tokenHash: 'a'.repeat(64),
    inviteeLabel: null,
    role: 'editor',
    createdAt: '2026-02-27T00:00:00.000Z',
    createdBy: 'owner-1',
    expiresAt: '2026-03-01T00:00:00.000Z',
    maxUses: 1,
    useCount: 0,
    consumedAt: null,
    consumedBy: null,
    revokedAt: null,
    revokedBy: null,
    status,
  }
}

test('treats non-owner active members as active shares', () => {
  assert.equal(hasPendingOrActiveShares([member('owner'), member('editor')], []), true)
})

test('treats active invites as pending shares', () => {
  assert.equal(hasPendingOrActiveShares([member('owner')], [invite('active')]), true)
})

test('ignores inactive invite statuses when owner is alone', () => {
  const invites = [invite('revoked'), invite('expired'), invite('consumed')]
  assert.equal(hasPendingOrActiveShares([member('owner')], invites), false)
})
