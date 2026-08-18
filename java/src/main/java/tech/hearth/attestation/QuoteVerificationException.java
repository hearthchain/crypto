package tech.hearth.attestation;

/** Thrown when a TDX DCAP quote is malformed or its authenticity chain does not check out. */
public final class QuoteVerificationException extends RuntimeException {
    public QuoteVerificationException(String message) {
        super(message);
    }

    public QuoteVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
