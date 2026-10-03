const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export async function sendMessage() {
  await wait(1200)
  return { reply: 'Sample text' }
}
