/*
 * Copyright (c) 2001
 *	Fortress Technologies, Inc.  All rights reserved.
 *      Charlie Lenahan (clenahan@fortresstech.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: IEEE 802.11 printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "netdissect.h"

#include "extract.h"

#include "cpack.h"


/* Lengths of 802.11 header components. */
#define	IEEE802_11_FC_LEN		2
#define	IEEE802_11_DUR_LEN		2
#define	IEEE802_11_DA_LEN		6
#define	IEEE802_11_SA_LEN		6
#define	IEEE802_11_BSSID_LEN		6
#define	IEEE802_11_RA_LEN		6
#define	IEEE802_11_TA_LEN		6
#define	IEEE802_11_ADDR1_LEN		6
#define	IEEE802_11_SEQ_LEN		2
#define	IEEE802_11_CTL_LEN		2
#define	IEEE802_11_CARRIED_FC_LEN	2
#define	IEEE802_11_HT_CONTROL_LEN	4
#define	IEEE802_11_IV_LEN		3
#define	IEEE802_11_KID_LEN		1

/* Frame check sequence length. */
#define	IEEE802_11_FCS_LEN		4

/* Lengths of beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2

#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2

/* Length of previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

#define	T_MGMT 0x0  /* management */
#define	T_CTRL 0x1  /* control */
#define	T_DATA 0x2  /* data */
#define	T_RESV 0x3  /* reserved */

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_QOS(x)		((x) & 0x08)

/*
 * Bits in the frame control field.
 */
#define	FC_VERSION(fc)      ((fc) & 0x3)
#define	FC_TYPE(fc)         (((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)      (((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)        ((fc) & 0x0100)
#define	FC_FROM_DS(fc)      ((fc) & 0x0200)
#define FC_TF_DS_BITS(fc)   (((fc) >> 8) & 0x3)

#define	MGMT_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+\
			 IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)

#define	CTRL_CONTROL_WRAPPER_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
					 IEEE802_11_ADDR1_LEN+\
					 IEEE802_11_CARRIED_FC_LEN+\
					 IEEE802_11_HT_CONTROL_LEN)

#define	CTRL_RTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN)

#define	CTRL_CTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

#define	CTRL_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

#define	CTRL_PS_POLL_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_AID_LEN+\
				 IEEE802_11_BSSID_LEN+IEEE802_11_TA_LEN)

#define	CTRL_END_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

#define	CTRL_END_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
				 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

#define	CTRL_BA_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

#define	CTRL_BAR_HDRLEN		(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
				 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN+\
				 IEEE802_11_CTL_LEN+IEEE802_11_SEQ_LEN)

/*
 *  Data Frame - Address field contents
 *
 *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
 *    0    |  0      |  DA    | SA     | BSSID  | n/a
 *    0    |  1      |  DA    | BSSID  | SA     | n/a
 *    1    |  0      |  BSSID | SA     | DA     | n/a
 *    1    |  1      |  RA    | TA     | DA     | SA
 */

/*
 * Function to get source and destination MAC addresses for a data frame.
 */
#if 0
static void
get_data_src_dst_mac(uint16_t fc, const u_char *p, const uint8_t **srcp,
                     const uint8_t **dstp)
{
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

	if (!FC_TO_DS(fc)) {
		if (!FC_FROM_DS(fc)) {
			/* not To DS and not From DS */
			*srcp = ADDR2;
			*dstp = ADDR1;
		} else {
			/* not To DS and From DS */
			*srcp = ADDR3;
			*dstp = ADDR1;
		}
	} else {
		if (!FC_FROM_DS(fc)) {
			/* From DS and not To DS */
			*srcp = ADDR2;
			*dstp = ADDR3;
		} else {
			/* To DS and From DS */
			*srcp = ADDR4;
			*dstp = ADDR3;
		}
	}

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}
#endif

static int extract_qos(uint16_t fc)
{
    char *ftds[4] = {"NO", "T", "F", "FT"};
    printf("Direct: %s", ftds[FC_TF_DS_BITS(fc)]);
	switch (FC_TYPE(fc)) {
	case T_MGMT:
        printf(" MGMT\n");
        break;
	case T_CTRL:
        printf(" CTRL\n");
        break;
	case T_DATA:
        printf(" DATA\n");
		return (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)));
	default:
        printf(" NONE\n");
        break;
	}
    return 0;
}

static u_int ieee802_11_print(const u_char *p, u_int length, u_int orig_caplen, int pad, u_int fcslen)
{
    char qos = 0;
	uint16_t fc;
	u_int caplen, hdrlen;

	caplen = orig_caplen;
	/* Remove FCS, if present */
	if (length < fcslen) {
		return caplen;
	}
	length -= fcslen;
	if (caplen > length) {
		/* Amount of FCS in actual packet data, if any */
		fcslen = caplen - length;
		caplen -= fcslen;
	}

	if (caplen < IEEE802_11_FC_LEN) {
		return orig_caplen;
	}

	fc = EXTRACT_LE_U_2(p);
	qos = extract_qos(fc);
	/*
	 * Go past the 802.11 header.
	 */
	length -= hdrlen;
	caplen -= hdrlen;
	p += hdrlen;

	return hdrlen;
}

/* $FreeBSD: src/sys/net80211/ieee80211_radiotap.h,v 1.5 2005/01/22 20:12:05 sam Exp $ */
/* NetBSD: ieee802_11_radio.h,v 1.2 2006/02/26 03:04:03 dyoung Exp  */

/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/* A generic radio capture format is desirable. It must be
 * rigidly defined (e.g., units for fields should be given),
 * and easily extensible.
 *
 * The following is an extensible radio capture format. It is
 * based on a bitmap indicating which fields are present.
 *
 * I am trying to describe precisely what the application programmer
 * should expect in the following, and for that reason I tell the
 * units and origin of each measurement (where it applies), or else I
 * use sufficiently weaselly language ("is a monotonically nondecreasing
 * function of...") that I cannot set false expectations for lawyerly
 * readers.
 */

/*
 * The radio capture header precedes the 802.11 header.
 *
 * Note well: all radiotap fields are little-endian.
 */
struct ieee80211_radiotap_header {
	nd_uint8_t	it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	nd_uint8_t	it_pad;
	nd_uint16_t	it_len;		/* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	nd_uint32_t	it_present;	/* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
};

/* Name                                 Data type       Units
 * ----                                 ---------       -----
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_VENDOR_NAMESPACE
 *					uint8_t  OUI[3]
 *                                   uint8_t  subspace
 *                                   uint16_t length
 *
 *     The Vendor Namespace Field contains three sub-fields. The first
 *     sub-field is 3 bytes long. It contains the vendor's IEEE 802
 *     Organizationally Unique Identifier (OUI). The fourth byte is a
 *     vendor-specific "namespace selector."
 *
 */
enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
static int print_radiotap_field(struct cpack_state *s, uint32_t bit, uint8_t *flagsp, uint32_t presentflags)
{
    int rc;

	switch (bit) {
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: {
            int8_t dbm_antsignal;
            rc = cpack_int8(s, &dbm_antsignal);
            if (rc != 0)
                goto trunc;
            printf("%ddBm signal ", dbm_antsignal > 0 ? dbm_antsignal - 128 : dbm_antsignal);
            break;
		}

	default:
		/* this bit indicates a field whose
		 * size we do not know, so we cannot
		 * proceed.  Just print the bit number.
		 */
        if (bit <= 14 || (bit >= 18 && bit < IEEE80211_RADIOTAP_NAMESPACE))
            break;
		return -1;
	}

	return 0;

trunc:
	return -1;
}


static int print_in_radiotap_namespace(struct cpack_state *s, uint8_t *flags,
                                       uint32_t presentflags, int bit0)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
	uint32_t present, next_present;
	int bitno;
	enum ieee80211_radiotap_type bit;
	int rc;

	for (present = presentflags; present; present = next_present) {
		/*
		 * Clear the least significant bit that is set.
		 */
		next_present = present & (present - 1);

		/*
		 * Get the bit number, within this presence word,
		 * of the remaining least significant bit that
		 * is set.
		 */
		bitno = BITNO_32(present ^ next_present);

		/*
		 * Stop if this is one of the "same meaning
		 * in all presence flags" bits.
		 */
		if (bitno >= IEEE80211_RADIOTAP_NAMESPACE)
			break;

		/*
		 * Get the radiotap bit number of that bit.
		 */
		bit = (enum ieee80211_radiotap_type)(bit0 + bitno);

		rc = print_radiotap_field(s, bit, flags, presentflags);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static u_int ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen)
{
#define	BIT(n)	(1U << n)
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_U_4(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	const struct ieee80211_radiotap_header *hdr;
	uint32_t presentflags;
	const nd_uint32_t *presentp, *last_presentp;
	int vendor_namespace;
	uint8_t vendor_oui[3];
	uint8_t vendor_subnamespace;
	uint16_t skip_length;
	int bit0;
	u_int len;
	uint8_t flags;
	int pad;
	u_int fcslen;

	if (caplen < sizeof(*hdr)) {
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;

	len = EXTRACT_LE_U_2(hdr->it_len);
	if (len < sizeof(*hdr)) {
		/*
		 * The length is the length of the entire header, so
		 * it must be as large as the fixed-length part of
		 * the header.
		 */
		return caplen;
	}
    printf("len: %lu, length:%u ", len - sizeof(*hdr), length);

	/*
	 * If we don't have the entire radiotap header, just give up.
	 */
	if (caplen < len) {
		return caplen;
	}
	cpack_init(&cpacker, (const uint8_t *)hdr, len); /* align against header start */
	cpack_advance(&cpacker, sizeof(*hdr)); /* includes the 1st bitmap */
	for (last_presentp = &hdr->it_present;
	     (const u_char*)(last_presentp + 1) <= p + len &&
	     IS_EXTENDED(last_presentp);
	     last_presentp++)
	  cpack_advance(&cpacker, sizeof(hdr->it_present)); /* more bitmaps */

	/* are there more bitmap extensions than bytes in header? */
	if ((const u_char*)(last_presentp + 1) > p + len) {
		return caplen;
	}

	/*
	 * Start out at the beginning of the default radiotap namespace.
	 */
	bit0 = 0;
	vendor_namespace = 0;
	memset(vendor_oui, 0, 3);
	vendor_subnamespace = 0;
	skip_length = 0;
	/* Assume no flags */
	flags = 0;
	/* Assume no Atheros padding between 802.11 header and body */
	pad = 0;
	/* Assume no FCS at end of frame */
	fcslen = 0;
	for (presentp = &hdr->it_present; presentp <= last_presentp;
	    presentp++) {
		presentflags = EXTRACT_LE_U_4(presentp);

		/*
		 * If this is a vendor namespace, we don't handle it.
		 */
		if (vendor_namespace) {
			/*
			 * Skip past the stuff we don't understand.
			 * If we add support for any vendor namespaces,
			 * it'd be added here; use vendor_oui and
			 * vendor_subnamespace to interpret the fields.
			 */
			if (cpack_advance(&cpacker, skip_length) != 0) {
				/*
				 * Ran out of space in the packet.
				 */
				break;
			}

			/*
			 * We've skipped it all; nothing more to
			 * skip.
			 */
			skip_length = 0;
		} else {
			if (print_in_radiotap_namespace(&cpacker,
			    &flags, presentflags, bit0) != 0) {
				/*
				 * Fatal error - can't process anything
				 * more in the radiotap header.
				 */
				break;
			}
		}

		/*
		 * Handle the namespace switch bits; we've already handled
		 * the extension bit in all but the last word above.
		 */
		switch (presentflags &
		    (BIT(IEEE80211_RADIOTAP_NAMESPACE)|BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))) {

		case 0:
			/*
			 * We're not changing namespaces.
			 * advance to the next 32 bits in the current
			 * namespace.
			 */
			bit0 += 32;
			break;

		case BIT(IEEE80211_RADIOTAP_NAMESPACE):
			/*
			 * We're switching to the radiotap namespace.
			 * Reset the presence-bitmap index to 0, and
			 * reset the namespace to the default radiotap
			 * namespace.
			 */
			bit0 = 0;
			vendor_namespace = 0;
			memset(vendor_oui, 0, 3);
			vendor_subnamespace = 0;
			skip_length = 0;
			break;

		case BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE):
			/*
			 * We're switching to a vendor namespace.
			 * Reset the presence-bitmap index to 0,
			 * note that we're in a vendor namespace,
			 * and fetch the fields of the Vendor Namespace
			 * item.
			 */
			bit0 = 0;
			vendor_namespace = 1;
			if ((cpack_align_and_reserve(&cpacker, 2)) == NULL) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[0]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[1]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[2]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_subnamespace) != 0) {
				break;
			}
			if (cpack_uint16(&cpacker, &skip_length) != 0) {
				break;
			}
			break;

		default:
			/*
			 * Illegal combination.  The behavior in this
			 * case is undefined by the radiotap spec; we
			 * just ignore both bits.
			 */
			break;
		}
	}

	if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
		pad = 1;	/* Atheros padding */
	if (flags & IEEE80211_RADIOTAP_F_FCS)
		fcslen = 4;	/* FCS at end of packet */
	return len + ieee802_11_print(p + len, length - len, caplen - len, pad,
	    fcslen);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}

/*
 * For DLT_IEEE802_11_RADIO; like DLT_IEEE802_11, but with an extra
 * header, containing information such as radio information.
 */
int awss_ieee802_11_radio_if_print(const struct pcap_pkthdr *h, const u_char *p)
{
	return ieee802_11_radio_print(p, h->len, h->caplen);
}
