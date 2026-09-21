/* tdx-quote-gen: generate a TDX quote with caller-specified report data.
 *
 * test_tdx_attest (from suse-libtdx-attest-devel) always uses random report
 * data, which is fine for plain attestation but not for RCAR flows where the
 * quote's report_data must be bound to a TEE public key (report_data =
 * sha384 of the canonical JSON runtime data, zero-padded to 64 bytes).
 *
 * Usage: tdx-quote-gen <128-hex-char report data> [quote-out-file]
 * Writes the raw quote to the output file (default: ./quote.dat).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tdx_attest.h>

static int hex2bin(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    if (strlen(hex) != out_len * 2)
        return -1;
    for (i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    tdx_report_data_t rd;
    uint8_t *quote = NULL;
    uint32_t quote_size = 0;
    tdx_attest_error_t err;
    const char *out;
    FILE *f;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <128-hex report-data> [quote-out-file]\n",
                argv[0]);
        return 2;
    }
    if (hex2bin(argv[1], rd.d, sizeof(rd.d)) != 0) {
        fprintf(stderr, "report data must be exactly %zu hex chars\n",
                sizeof(rd.d) * 2);
        return 2;
    }

    err = tdx_att_get_quote(&rd, NULL, 0, NULL, &quote, &quote_size, 0);
    if (err != TDX_ATTEST_SUCCESS || !quote) {
        fprintf(stderr, "tdx_att_get_quote failed: %d\n", (int)err);
        return 1;
    }

    out = argc > 2 ? argv[2] : "quote.dat";
    f = fopen(out, "wb");
    if (!f) {
        perror("fopen");
        tdx_att_free_quote(quote);
        return 1;
    }
    if (fwrite(quote, 1, quote_size, f) != quote_size) {
        fprintf(stderr, "short write to %s\n", out);
        fclose(f);
        tdx_att_free_quote(quote);
        return 1;
    }
    fclose(f);
    tdx_att_free_quote(quote);
    return 0;
}
