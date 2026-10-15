import 'reflect-metadata'
import nodeCrypto from 'node:crypto'
import * as x509 from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { mdocContext } from './context'

x509.cryptoProvider.set(nodeCrypto.webcrypto as unknown as Crypto)

const hour = 60 * 60 * 1000
const day = 24 * hour
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' }

const generateKeys = async () =>
  (await nodeCrypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as unknown as CryptoKeyPair

/**
 * A root certificate valid from ten days ago to ten days from now.
 */
async function createRoot() {
  const keys = await generateKeys()
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test IACA, C=NL',
    notBefore: new Date(Date.now() - 10 * day),
    notAfter: new Date(Date.now() + 10 * day),
    signingAlgorithm,
    keys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  })

  return { certificate, keys }
}

/**
 * A leaf issued under the root's name, valid between the given offsets from now and signed with the root key
 * unless another signing key is given.
 */
async function createLeaf(
  root: Awaited<ReturnType<typeof createRoot>>,
  options: { notBefore: number; notAfter: number; signingKey?: CryptoKey }
) {
  const keys = await generateKeys()
  return x509.X509CertificateGenerator.create({
    serialNumber: '02',
    issuer: root.certificate.subject,
    subject: 'CN=Test Document Signer, C=NL',
    notBefore: new Date(Date.now() + options.notBefore),
    notAfter: new Date(Date.now() + options.notAfter),
    signingAlgorithm,
    publicKey: keys.publicKey,
    signingKey: options.signingKey ?? root.keys.privateKey,
  })
}

const verifyChain = (options: { leaf: x509.X509Certificate; trusted: x509.X509Certificate; now?: Date }) =>
  mdocContext.x509.verifyCertificateChain({
    trustedCertificates: [new Uint8Array(options.trusted.rawData)],
    x5chain: [new Uint8Array(options.leaf.rawData)],
    now: options.now,
  })

describe('example context verifyCertificateChain', () => {
  test('accepts a leaf within its validity period', async () => {
    const root = await createRoot()
    const leaf = await createLeaf(root, { notBefore: -hour, notAfter: hour })

    await expect(verifyChain({ leaf, trusted: root.certificate })).resolves.toHaveProperty('chain')
  })

  test('rejects an expired leaf', async () => {
    const root = await createRoot()
    const leaf = await createLeaf(root, { notBefore: -2 * day, notAfter: -day })

    await expect(verifyChain({ leaf, trusted: root.certificate })).rejects.toThrow('is not valid at')
  })

  test('rejects a leaf that is not yet valid', async () => {
    const root = await createRoot()
    const leaf = await createLeaf(root, { notBefore: day, notAfter: 2 * day })

    await expect(verifyChain({ leaf, trusted: root.certificate })).rejects.toThrow('is not valid at')
  })

  test('rejects a leaf that is not signed by the root key', async () => {
    const root = await createRoot()
    const otherKeys = await generateKeys()
    const leaf = await createLeaf(root, { notBefore: -hour, notAfter: hour, signingKey: otherKeys.privateKey })

    await expect(verifyChain({ leaf, trusted: root.certificate })).rejects.toThrow('No trusted certificate was found')
  })

  test('checks the validity period at the given time', async () => {
    const root = await createRoot()
    const valid = await createLeaf(root, { notBefore: -hour, notAfter: hour })
    const expired = await createLeaf(root, { notBefore: -2 * day, notAfter: -day })

    await expect(
      verifyChain({ leaf: valid, trusted: root.certificate, now: new Date(Date.now() + 2 * hour) })
    ).rejects.toThrow('is not valid at')
    await expect(
      verifyChain({ leaf: expired, trusted: root.certificate, now: new Date(Date.now() - 1.5 * day) })
    ).resolves.toHaveProperty('chain')
  })

  test('accepts a leaf at its notBefore and notAfter instants', async () => {
    const root = await createRoot()
    const leaf = await createLeaf(root, { notBefore: -hour, notAfter: hour })

    await expect(verifyChain({ leaf, trusted: root.certificate, now: leaf.notBefore })).resolves.toHaveProperty('chain')
    await expect(verifyChain({ leaf, trusted: root.certificate, now: leaf.notAfter })).resolves.toHaveProperty('chain')
  })

  test('rejects an expired leaf that is itself trusted', async () => {
    const root = await createRoot()
    const leaf = await createLeaf(root, { notBefore: -2 * day, notAfter: -day })

    await expect(verifyChain({ leaf, trusted: leaf })).rejects.toThrow('is not valid at')
  })
})
