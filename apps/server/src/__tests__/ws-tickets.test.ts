import test from 'node:test'
import assert from 'node:assert/strict'

const { clearWsTicketsForTests, consumeWsTicket, issueWsTicket } = await import('../security/ws-tickets.js')

test('websocket ticket is one-time use', () => {
  clearWsTicketsForTests()

  const issued = issueWsTicket({
    folderId: 'folder-1',
    clientId: 'member-1',
    tokenVersion: 3,
    roomName: 'folder:folder-1:doc:notes.md',
  })

  const consumed = consumeWsTicket(issued.ticket)
  assert.ok(consumed)
  assert.equal(consumed?.folderId, 'folder-1')
  assert.equal(consumed?.clientId, 'member-1')
  assert.equal(consumed?.tokenVersion, 3)

  const secondConsume = consumeWsTicket(issued.ticket)
  assert.equal(secondConsume, null)
})
