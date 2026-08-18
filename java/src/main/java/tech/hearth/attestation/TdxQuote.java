package tech.hearth.attestation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tech.hearth.crypto.Crypto;

/**
 * A verified Intel TDX DCAP quote (v4, ECDSA-256-with-P-256 attestation key).
 *
 * <p>{@link #verify} checks the offline signature chain a quote carries in
 * itself, with no network access:
 *
 * <pre>
 *   quote signature ------------------ verified by --&gt; attestation key
 *   attestation key + qe_auth_data --- hashed into  --&gt; QE report's report_data
 *   QE report signature -------------- verified by --&gt; PCK leaf certificate
 *   PCK leaf &lt;- PCK intermediate CA &lt;- Intel SGX Root CA (hardcoded trust anchor)
 * </pre>
 *
 * <p>That proves the quote was produced by genuine Intel TDX hardware and
 * that {@link #reportData()} is exactly what that hardware measured —
 * including, via {@link #bindsPublicKey}, that a public key handed to the
 * caller out of band really did come from inside the attested TD.
 *
 * <p><strong>What this does not check:</strong> TCB freshness (whether the
 * platform's firmware/microcode is up to date) or certificate revocation,
 * both of which need live collateral fetched from Intel PCS. hearth-chain's
 * miner delegates that to {@code secretvm-cli verify quote} (see
 * {@code scripts/verify-node.sh} in the miner repo); a caller that needs a
 * TCB verdict too still needs a live DCAP verifier for that part. This class
 * covers the offline half: the part that makes the quote's signature, and
 * its binding to a public key, trustworthy on their own.
 *
 * <p>Ported from the parsing tables in
 * {@code github.com/google/go-tdx-guest}'s {@code abi} and {@code verify}
 * packages (the library the miner uses to fetch, but not verify, its own
 * quote) — see {@code internal/enclave/attest_linux.go} in the miner repo.
 */
public final class TdxQuote {

    private static final int VERSION_V4 = 4;
    private static final int ATTESTATION_KEY_TYPE_ECDSA_P256 = 2;
    private static final int TEE_TYPE_TDX = 0x00000081;
    private static final int QE_REPORT_CERTIFICATION_DATA_TYPE = 6;
    private static final int PCK_CERTIFICATE_CHAIN_DATA_TYPE = 5;

    private static final int HEADER_START = 0x00;
    private static final int HEADER_SIZE = 0x30;
    private static final int BODY_START = HEADER_START + HEADER_SIZE;
    private static final int BODY_SIZE = 0x248;
    private static final int SIGNED_DATA_SIZE_START = BODY_START + BODY_SIZE;
    private static final int SIGNED_DATA_SIZE_FIELD_LEN = 4;
    private static final int SIGNED_DATA_START = SIGNED_DATA_SIZE_START + SIGNED_DATA_SIZE_FIELD_LEN;
    private static final int QUOTE_MIN_SIZE = 0x3FC;

    private static final int SIGNATURE_SIZE = 0x40;
    private static final int ATTESTATION_KEY_SIZE = 0x40;
    private static final int QE_REPORT_SIZE = 0x180;
    private static final int QE_REPORT_SIGNATURE_SIZE = 0x40;

    private static final int REPORT_DATA_SIZE = 0x40;
    private static final int MEASUREMENT_SIZE = 0x30;
    private static final int RTMR_COUNT = 4;

    private static final Pattern PEM_CERTIFICATE =
            Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final X509Certificate TRUSTED_INTEL_ROOT = loadTrustedIntelRoot();

    private final byte[] mrSeam;
    private final byte[] mrTd;
    private final byte[][] rtmrs;
    private final byte[] reportData;

    private TdxQuote(byte[] mrSeam, byte[] mrTd, byte[][] rtmrs, byte[] reportData) {
        this.mrSeam = mrSeam;
        this.mrTd = mrTd;
        this.rtmrs = rtmrs;
        this.reportData = reportData;
    }

    /** The measurement of the TDX module (SEAM) that produced this quote. */
    public byte[] mrSeam() {
        return mrSeam.clone();
    }

    /** MRTD: the measurement of the TD's initial image, extended at build time. */
    public byte[] mrTd() {
        return mrTd.clone();
    }

    /** RTMR0..RTMR3: the four runtime-extendable measurement registers. */
    public byte[] rtmr(int index) {
        return rtmrs[index].clone();
    }

    /** The 64-byte REPORTDATA the TD asked to have bound into this quote. */
    public byte[] reportData() {
        return reportData.clone();
    }

    /**
     * True if {@code reportData} is exactly {@code publicKey} in its first 32
     * bytes and zero in the rest — the layout {@code enclave.Identity} in the
     * miner writes ({@code copy(reportData[:32], pub)}, the tail left zero).
     * A quote that passed {@link #verify} and satisfies this proves
     * {@code publicKey} was generated inside, and never left, the attested TD.
     */
    public boolean bindsPublicKey(byte[] publicKey) {
        if (publicKey.length > REPORT_DATA_SIZE) {
            return false;
        }
        byte[] expected = Arrays.copyOf(publicKey, REPORT_DATA_SIZE);
        return Arrays.equals(expected, reportData);
    }

    /** {@link #verify(byte[], Instant)} at the current time. */
    public static TdxQuote verify(byte[] raw) {
        return verify(raw, Instant.now());
    }

    /**
     * Parse and fully authenticate a raw TDX v4 DCAP quote.
     *
     * @param now the instant to check the PCK certificate chain's validity
     *            period against
     * @throws QuoteVerificationException if the quote is malformed, any
     *         signature in its chain fails to verify, or the PCK certificate
     *         chain does not lead to the hardcoded Intel SGX Root CA
     */
    public static TdxQuote verify(byte[] raw, Instant now) {
        if (raw.length < QUOTE_MIN_SIZE) {
            throw new QuoteVerificationException(
                    "quote is %d bytes, expected at least %d".formatted(raw.length, QUOTE_MIN_SIZE));
        }
        checkHeader(raw);

        int signedDataSize = readU32LE(raw, SIGNED_DATA_SIZE_START);
        requireLength(raw, SIGNED_DATA_START, signedDataSize, "signed data");

        byte[] quoteSignature = slice(raw, SIGNED_DATA_START, SIGNATURE_SIZE);
        int attestationKeyStart = SIGNED_DATA_START + SIGNATURE_SIZE;
        byte[] attestationKeyRaw = slice(raw, attestationKeyStart, ATTESTATION_KEY_SIZE);

        int certificationDataStart = attestationKeyStart + ATTESTATION_KEY_SIZE;
        int certDataType = readU16LE(raw, certificationDataStart);
        if (certDataType != QE_REPORT_CERTIFICATION_DATA_TYPE) {
            throw new QuoteVerificationException(
                    "certification data type is %d, expected QE report certification data (%d)"
                            .formatted(certDataType, QE_REPORT_CERTIFICATION_DATA_TYPE));
        }
        int certDataSize = readU32LE(raw, certificationDataStart + 2);
        int certDataStart = certificationDataStart + 6;
        requireLength(raw, certDataStart, certDataSize, "QE report certification data");

        byte[] qeReport = slice(raw, certDataStart, QE_REPORT_SIZE);
        int qeReportSignatureStart = certDataStart + QE_REPORT_SIZE;
        byte[] qeReportSignature = slice(raw, qeReportSignatureStart, QE_REPORT_SIGNATURE_SIZE);

        int qeAuthDataStart = qeReportSignatureStart + QE_REPORT_SIGNATURE_SIZE;
        int qeAuthDataLen = readU16LE(raw, qeAuthDataStart);
        byte[] qeAuthData = slice(raw, qeAuthDataStart + 2, qeAuthDataLen);

        int pckChainStart = qeAuthDataStart + 2 + qeAuthDataLen;
        int pckChainType = readU16LE(raw, pckChainStart);
        if (pckChainType != PCK_CERTIFICATE_CHAIN_DATA_TYPE) {
            throw new QuoteVerificationException(
                    "PCK certificate chain data type is %d, expected %d"
                            .formatted(pckChainType, PCK_CERTIFICATE_CHAIN_DATA_TYPE));
        }
        int pckChainSize = readU32LE(raw, pckChainStart + 2);
        byte[] pckChainPem = slice(raw, pckChainStart + 6, pckChainSize);

        X509Certificate[] chain = parsePckCertificateChain(pckChainPem);
        X509Certificate leaf = chain[0];
        X509Certificate intermediate = chain[1];

        verifyQuoteSignature(raw, attestationKeyRaw, quoteSignature);
        verifyQeReportSignature(qeReport, qeReportSignature, leaf);
        verifyAttestationKeyBoundToQeReport(attestationKeyRaw, qeAuthData, qeReport);
        verifyPckCertificateChain(leaf, intermediate, now);

        byte[] mrSeam = slice(raw, BODY_START + 0x10, MEASUREMENT_SIZE);
        byte[] mrTd = slice(raw, BODY_START + 0x88, MEASUREMENT_SIZE);
        byte[][] rtmrs = new byte[RTMR_COUNT][];
        for (int i = 0; i < RTMR_COUNT; i++) {
            rtmrs[i] = slice(raw, BODY_START + 0x148 + i * MEASUREMENT_SIZE, MEASUREMENT_SIZE);
        }
        byte[] reportData = slice(raw, BODY_START + 0x208, REPORT_DATA_SIZE);

        return new TdxQuote(mrSeam, mrTd, rtmrs, reportData);
    }

    // ---------------------------------------------------------------- steps

    private static void checkHeader(byte[] raw) {
        int version = readU16LE(raw, 0x00);
        if (version != VERSION_V4) {
            throw new QuoteVerificationException("quote version %d is not supported, expected %d"
                    .formatted(version, VERSION_V4));
        }
        int attestationKeyType = readU16LE(raw, 0x02);
        if (attestationKeyType != ATTESTATION_KEY_TYPE_ECDSA_P256) {
            throw new QuoteVerificationException(
                    "attestation key type %d is not supported, expected ECDSA-256-with-P-256 (%d)"
                            .formatted(attestationKeyType, ATTESTATION_KEY_TYPE_ECDSA_P256));
        }
        long teeType = readU32LE(raw, 0x04) & 0xFFFFFFFFL;
        if (teeType != TEE_TYPE_TDX) {
            throw new QuoteVerificationException(
                    "TEE type 0x%08x is not TDX (0x%08x)".formatted(teeType, TEE_TYPE_TDX));
        }
    }

    /** The quote signature over header||body, verified with the embedded (as-yet unauthenticated) attestation key. */
    private static void verifyQuoteSignature(byte[] raw, byte[] attestationKeyRaw, byte[] signature) {
        ECPublicKey attestationKey = ecPublicKeyFromRaw(attestationKeyRaw);
        byte[] message = slice(raw, HEADER_START, HEADER_SIZE + BODY_SIZE);
        if (!ecdsaVerify(attestationKey, message, signature)) {
            throw new QuoteVerificationException("quote signature does not verify against the attestation key");
        }
    }

    /** The QE report's signature, verified with the PCK leaf certificate — this is what authenticates the QE report. */
    private static void verifyQeReportSignature(byte[] qeReport, byte[] signature, X509Certificate pckLeaf) {
        if (!ecdsaVerify((ECPublicKey) pckLeaf.getPublicKey(), qeReport, signature)) {
            throw new QuoteVerificationException("QE report signature does not verify against the PCK leaf certificate");
        }
    }

    /**
     * Ties the (otherwise self-certified) attestation key to the PCK-authenticated QE report: the QE report's
     * report_data must be exactly SHA-256(attestation key || QE auth data), zero-padded to 64 bytes.
     */
    private static void verifyAttestationKeyBoundToQeReport(byte[] attestationKeyRaw, byte[] qeAuthData, byte[] qeReport) {
        byte[] attestKeyAndAuthData = concat(attestationKeyRaw, qeAuthData);
        byte[] hash = Crypto.defaultBackend().sha256(attestKeyAndAuthData);
        byte[] expected = Arrays.copyOf(hash, REPORT_DATA_SIZE);
        byte[] qeReportData = slice(qeReport, 0x140, REPORT_DATA_SIZE);
        if (!Arrays.equals(expected, qeReportData)) {
            throw new QuoteVerificationException(
                    "QE report's report_data does not match SHA-256(attestation key || QE auth data); "
                            + "the attestation key is not the one the PCK certificate authenticated");
        }
    }

    /** leaf &lt;- intermediate &lt;- Intel SGX Root CA, checked by name, by signature, and by PKIX path validation. */
    private static void verifyPckCertificateChain(X509Certificate leaf, X509Certificate intermediate, Instant now) {
        requireSubjectCommonName(leaf, "Intel SGX PCK Certificate");
        String intermediateCn = intermediate.getSubjectX500Principal().getName();
        if (!intermediateCn.contains("CN=Intel SGX PCK Platform CA") && !intermediateCn.contains("CN=Intel SGX PCK Processor CA")) {
            throw new QuoteVerificationException(
                    "PCK intermediate certificate has unexpected subject: " + intermediateCn);
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var path = factory.generateCertPath(List.of(leaf, intermediate));
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(TRUSTED_INTEL_ROOT, null)));
            params.setRevocationEnabled(false);
            params.setDate(Date.from(now));
            CertPathValidator.getInstance("PKIX").validate(path, params);
        } catch (CertPathValidatorException e) {
            throw new QuoteVerificationException(
                    "PCK certificate chain does not lead to the trusted Intel SGX Root CA: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new QuoteVerificationException("PCK certificate chain validation failed", e);
        }
    }

    private static void requireSubjectCommonName(X509Certificate cert, String expected) {
        String name = cert.getSubjectX500Principal().getName();
        if (!name.contains("CN=" + expected)) {
            throw new QuoteVerificationException(
                    "certificate has unexpected subject %s, expected CN=%s".formatted(name, expected));
        }
    }

    // ------------------------------------------------------------- parsing

    private static X509Certificate[] parsePckCertificateChain(byte[] pem) {
        List<X509Certificate> certs = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Matcher matcher = PEM_CERTIFICATE.matcher(new String(pem, StandardCharsets.US_ASCII));
            while (matcher.find()) {
                byte[] der = java.util.Base64.getMimeDecoder().decode(matcher.group(1));
                certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (GeneralSecurityException e) {
            throw new QuoteVerificationException("could not parse PCK certificate chain", e);
        }
        if (certs.size() != 3) {
            throw new QuoteVerificationException(
                    "PCK certificate chain has %d certificates, expected 3 (leaf, intermediate, root)"
                            .formatted(certs.size()));
        }
        return certs.toArray(new X509Certificate[0]);
    }

    private static X509Certificate loadTrustedIntelRoot() {
        try (InputStream in = TdxQuote.class.getResourceAsStream("/attestation/intel-sgx-root-ca.pem")) {
            if (in == null) {
                throw new IllegalStateException("bundled Intel SGX Root CA certificate is missing from the classpath");
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not parse the bundled Intel SGX Root CA certificate", e);
        }
    }

    // ------------------------------------------------------------ ecdsa/asn.1

    private static boolean ecdsaVerify(ECPublicKey publicKey, byte[] message, byte[] rawSignature) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(derFromRawSignature(rawSignature));
        } catch (GeneralSecurityException e) {
            throw new QuoteVerificationException("ECDSA verification failed", e);
        }
    }

    /** DHKEM-free, TDX quotes carry raw (32-byte x, 32-byte y) points; build the P-256 key and check it is on-curve. */
    private static ECPublicKey ecPublicKeyFromRaw(byte[] xy) {
        if (xy.length != ATTESTATION_KEY_SIZE) {
            throw new QuoteVerificationException("attestation key must be " + ATTESTATION_KEY_SIZE + " bytes");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(xy, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(xy, 32, 64));
        try {
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            if (!isOnCurve(x, y, spec)) {
                throw new QuoteVerificationException("attestation key is not a point on the P-256 curve");
            }
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        } catch (GeneralSecurityException e) {
            throw new QuoteVerificationException("invalid attestation key", e);
        }
    }

    /** y^2 = x^3 + a*x + b (mod p), the short-Weierstrass equation P-256 shares with every NIST prime curve. */
    private static boolean isOnCurve(BigInteger x, BigInteger y, ECParameterSpec spec) {
        EllipticCurve curve = spec.getCurve();
        ECField field = curve.getField();
        if (!(field instanceof ECFieldFp fieldFp)) {
            throw new QuoteVerificationException("unsupported EC field for P-256");
        }
        BigInteger p = fieldFp.getP();
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).multiply(x).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        return lhs.equals(rhs);
    }

    /** Raw {@code r(32) || s(32)} to the DER {@code SEQUENCE { INTEGER r, INTEGER s }} {@link Signature} expects. */
    private static byte[] derFromRawSignature(byte[] raw) {
        if (raw.length != SIGNATURE_SIZE) {
            throw new QuoteVerificationException("signature must be " + SIGNATURE_SIZE + " bytes");
        }
        byte[] r = derInteger(Arrays.copyOfRange(raw, 0, 32));
        byte[] s = derInteger(Arrays.copyOfRange(raw, 32, 64));
        byte[] body = concat(r, s);
        return concat(new byte[] {0x30, (byte) body.length}, body);
    }

    private static byte[] derInteger(byte[] value) {
        int start = 0;
        while (start < value.length - 1 && value[start] == 0) {
            start++;
        }
        boolean needsPad = (value[start] & 0x80) != 0;
        byte[] content = new byte[value.length - start + (needsPad ? 1 : 0)];
        System.arraycopy(value, start, content, needsPad ? 1 : 0, value.length - start);
        return concat(new byte[] {0x02, (byte) content.length}, content);
    }

    // ---------------------------------------------------------------- bytes

    private static void requireLength(byte[] raw, int start, int length, String field) {
        if (length < 0 || start + (long) length > raw.length) {
            throw new QuoteVerificationException(
                    "%s runs past the end of the quote (start %d, length %d, quote size %d)"
                            .formatted(field, start, length, raw.length));
        }
    }

    private static byte[] slice(byte[] raw, int start, int length) {
        requireLength(raw, start, length, "field");
        return Arrays.copyOfRange(raw, start, start + length);
    }

    private static int readU16LE(byte[] raw, int offset) {
        return (raw[offset] & 0xff) | ((raw[offset + 1] & 0xff) << 8);
    }

    private static int readU32LE(byte[] raw, int offset) {
        return (raw[offset] & 0xff) | ((raw[offset + 1] & 0xff) << 8)
                | ((raw[offset + 2] & 0xff) << 16) | ((raw[offset + 3] & 0xff) << 24);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
