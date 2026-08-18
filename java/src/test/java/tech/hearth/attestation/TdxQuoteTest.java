package tech.hearth.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import tech.hearth.crypto.Hex;

/**
 * Runs {@link TdxQuote#verify} against a real quote captured from a deployed
 * miner node (hearthchain/miner's {@code internal/enclave/testdata/attestation},
 * refreshed by that repo's {@code scripts/verify-node.sh}), pinned in
 * {@code meta.json} alongside it.
 */
class TdxQuoteTest {

    private static final String PUBKEY_HEX = "4f3b45b412ebaad3e862208bf45c7cb89f54aa84fdd40a58dc571c68fb53ca5b";
    private static final String MR_TD_HEX =
            "1e305ac8284517f73ada985bfc9fded48b23ed091ba8149678bb10207fb470c7903d7a8ddffa5a7be2a60e349bb75b6e";
    private static final String RTMR3_HEX =
            "de64404f9e163064eca60f6c7024e9112a8770e9441981b1d501e6575c89c591b5b3d648a4ce86b414fbad8eaf955b8d";

    private static byte[] realQuote() throws IOException {
        try (InputStream in = TdxQuoteTest.class.getResourceAsStream("/attestation/quote.hex")) {
            String hex = new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
            return Hex.decode(hex);
        }
    }

    @Test
    void verifiesAndParsesTheCapturedMinerQuote() throws IOException {
        TdxQuote quote = TdxQuote.verify(realQuote());

        assertArrayEquals(Hex.decode(MR_TD_HEX), quote.mrTd());
        assertArrayEquals(Hex.decode(RTMR3_HEX), quote.rtmr(3));

        byte[] pubkey = Hex.decode(PUBKEY_HEX);
        assertTrue(quote.bindsPublicKey(pubkey));
        assertArrayEquals(Arrays.copyOf(pubkey, 64), quote.reportData());
    }

    @Test
    void bindsPublicKeyRejectsAWrongKey() throws IOException {
        TdxQuote quote = TdxQuote.verify(realQuote());
        byte[] wrongKey = Hex.decode(PUBKEY_HEX);
        wrongKey[0] ^= 0x01;
        assertFalse(quote.bindsPublicKey(wrongKey));
    }

    @Test
    void rejectsATamperedQuoteSignature() throws IOException {
        byte[] raw = realQuote();
        // The quote signature sits right after header(48) + body(584) + signed-data-size(4).
        raw[48 + 0x248 + 4] ^= 0x01;
        assertThrows(QuoteVerificationException.class, () -> TdxQuote.verify(raw));
    }

    @Test
    void rejectsATamperedReportData() throws IOException {
        byte[] raw = realQuote();
        // report_data is the last field of the (signed) TD quote body.
        raw[48 + 0x208] ^= 0x01;
        assertThrows(QuoteVerificationException.class, () -> TdxQuote.verify(raw));
    }

    @Test
    void rejectsATamperedPckCertificateChain() throws IOException {
        byte[] raw = realQuote();
        raw[raw.length - 200] ^= 0x01;
        assertThrows(QuoteVerificationException.class, () -> TdxQuote.verify(raw));
    }

    @Test
    void rejectsATruncatedQuote() {
        assertThrows(QuoteVerificationException.class, () -> TdxQuote.verify(new byte[10]));
    }
}
