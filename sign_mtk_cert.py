#!/usr/bin/env python3

from pathlib import Path
import argparse
import struct
import hashlib
import sys

PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
PART_HDR_STRUCT = struct.Struct(PART_HDR_FORMAT)

IMG_TYPE_GROUP_CERT = (0x02 << 24)
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02

OID_IMAGE_HASH = "2.16.886.2454.2.1"
OID_IMAGE_HEADER_HASH = "2.16.886.2454.2.4"


def roundup(value, align):
    if align is None or align <= 0:
        return value
    return ((value + align - 1) // align) * align


class PartHdr:
    def __init__(self, values):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = values[2].split(b"\0", 1)[0].decode("latin-1")
        self.maddr = values[3]
        self.mode = values[4]
        self.ext_magic = values[5]
        self.hdr_sz = values[6]
        self.hdr_ver = values[7]
        self.img_type = values[8]
        self.img_list_end = values[9]
        self.align_sz = values[10]
        self.dsize_extend = values[11]
        self.maddr_extend = values[12]

    @classmethod
    def parse_from_bytes(cls, data, off):
        vals = PART_HDR_STRUCT.unpack_from(data, off)
        return cls(vals)

    def padded_data_size(self):
        return roundup(self.dsize, self.align_sz)

    @property
    def is_certificate(self):
        return (self.img_type & 0xff000000) == IMG_TYPE_GROUP_CERT

    @property
    def is_cert2(self):
        return self.img_type == IMG_TYPE_CERT2


def encode_length(n):
    if n < 0:
        raise ValueError("negative DER length")

    if n < 0x80:
        return bytes([n])

    s = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(s)]) + s


def encode_oid(oid):
    parts = [int(x) for x in oid.split(".")]

    if len(parts) < 2:
        raise ValueError(f"bad OID: {oid}")

    if parts[0] < 0 or parts[0] > 2:
        raise ValueError(f"bad first OID component: {oid}")

    if parts[1] < 0:
        raise ValueError(f"bad second OID component: {oid}")

    if parts[0] < 2 and parts[1] >= 40:
        raise ValueError(f"bad OID first two components: {oid}")

    def encode_base128(value):
        if value == 0:
            return b"\x00"

        tmp = []

        while value:
            tmp.append(value & 0x7f)
            value >>= 7

        tmp.reverse()

        result = bytearray()

        for i, v in enumerate(tmp):
            if i != len(tmp) - 1:
                result.append(0x80 | v)
            else:
                result.append(v)

        return bytes(result)

    out = bytearray()

    first = 40 * parts[0] + parts[1]
    out += encode_base128(first)

    for p in parts[2:]:
        if p < 0:
            raise ValueError(f"negative OID component: {oid}")
        out += encode_base128(p)

    return bytes(out)


def build_oid_tlv(oid):
    b = encode_oid(oid)
    return b"\x06" + encode_length(len(b)) + b


def build_bitstring_tlv(payload):
    # DER BIT STRING:
    # first content byte is the number of unused bits.
    return (
        b"\x03"
        + encode_length(len(payload) + 1)
        + b"\x00"
        + payload
    )


def load_pmc():
    try:
        import parse_mtk_certs as pmc
    except ImportError:
        print(
            "ERROR: parse_mtk_certs.py is required.",
            file=sys.stderr,
        )
        sys.exit(1)

    return pmc


def parse_part_headers(data):
    out = []
    off = 0
    file_size = len(data)
    idx = 0

    while off + PART_HDR_SIZE <= file_size:
        try:
            hdr = PartHdr.parse_from_bytes(data, off)
        except struct.error:
            break

        if hdr.magic != PART_MAGIC:
            break

        data_offset = off + PART_HDR_SIZE
        padded = hdr.padded_data_size()
        next_offset = data_offset + padded

        if data_offset + hdr.dsize > file_size:
            break

        if next_offset > file_size:
            break

        out.append(
            (
                idx,
                off,
                data_offset,
                next_offset,
                hdr,
            )
        )

        idx += 1
        off = next_offset

        if hdr.img_list_end:
            break

    return out


def parse_tlv_tree(data, base_off=0):
    pmc = load_pmc()

    nodes = []
    off = 0

    while off < len(data):
        try:
            (
                tag_class,
                constructed,
                tagnum,
                tag_bytes,
                tag_len,
            ) = pmc.read_tag(data, off)

            length, len_len = pmc.read_length(
                data,
                off + tag_len,
            )

            if length is None:
                break

        except Exception:
            break

        hdr_len = tag_len + len_len
        val_off = off + hdr_len
        val_end = val_off + length

        if val_end > len(data):
            break

        val = data[val_off:val_end]

        node = {
            "off": base_off + off,
            "local_off": off,
            "tag_class": tag_class,
            "constructed": constructed,
            "tagnum": tagnum,
            "hdr_len": hdr_len,
            "length": length,
            "val": None if constructed else val,
            "children": None,
            "tag_bytes": tag_bytes,
            "val_off": base_off + val_off,
            "end": base_off + val_end,
        }

        if constructed:
            node["children"] = parse_tlv_tree(
                val,
                base_off + val_off,
            )

        nodes.append(node)
        off = val_end

    return nodes


def iter_top_level_tlvs(data):
    pmc = load_pmc()

    off = 0

    while off < len(data):
        (
            tag_class,
            constructed,
            tagnum,
            tag_bytes,
            tag_len,
        ) = pmc.read_tag(data, off)

        length, len_len = pmc.read_length(
            data,
            off + tag_len,
        )

        if length is None:
            raise ValueError(
                f"indefinite DER length at 0x{off:x}"
            )

        hdr_len = tag_len + len_len
        end = off + hdr_len + length

        if end > len(data):
            raise ValueError(
                f"truncated DER TLV at 0x{off:x}"
            )

        yield {
            "off": off,
            "end": end,
            "tag_class": tag_class,
            "constructed": constructed,
            "tagnum": tagnum,
            "tag_bytes": tag_bytes,
            "hdr_len": hdr_len,
            "length": length,
            "val_off": off + hdr_len,
        }

        off = end


def decode_oid(value):
    pmc = load_pmc()

    try:
        return pmc.decode_oid(value)
    except Exception:
        return None


def find_first_bitstring(node):
    if node is None:
        return None

    if (
        node["tag_class"] == 0
        and node["tagnum"] == 3
        and node["val"] is not None
    ):
        return node["val"]

    for child in node.get("children") or []:
        result = find_first_bitstring(child)

        if result is not None:
            return result

    return None


def find_oid_bitstring(der, oid_str):
    """
    Locate the first matching OID and its following BIT STRING.

    Returns:
        (bitstring_with_unused_bits_prefix, oid_offset)
    """

    root_nodes = parse_tlv_tree(der)

    def walk(nodes):
        for i, node in enumerate(nodes):
            if (
                node["tag_class"] == 0
                and node["tagnum"] == 6
                and node["val"] is not None
            ):
                name = decode_oid(node["val"])

                if name == oid_str:
                    if i + 1 < len(nodes):
                        bs = find_first_bitstring(nodes[i + 1])

                        if bs is not None:
                            return bs, node["off"]

                    for j in range(i + 1, len(nodes)):
                        bs = find_first_bitstring(nodes[j])

                        if bs is not None:
                            return bs, node["off"]

                    return None, node["off"]

            if node.get("children"):
                result = walk(node["children"])

                if result[0] is not None:
                    return result

        return None, None

    return walk(root_nodes)


def find_original_cert2_der(cert2_blob):
    """
    Locate the underlying certificate DER.

    The returned offset is relative to the CERT2 logical blob.
    """

    for node in iter_top_level_tlvs(cert2_blob):
        if (
            node["tag_class"] == 0
            and node["constructed"]
            and node["tagnum"] == 0x10
        ):
            return (
                cert2_blob[node["off"]:node["end"]],
                node["off"],
                node["end"],
            )

    raise ValueError(
        "original CERT2 DER SEQUENCE (0x30) not found"
    )


def build_hash_override_block(header_digest, image_digest):
    parts = []

    if header_digest is not None:
        parts.append(
            build_oid_tlv(OID_IMAGE_HEADER_HASH)
        )
        parts.append(
            build_bitstring_tlv(header_digest)
        )

    if image_digest is not None:
        parts.append(
            build_oid_tlv(OID_IMAGE_HASH)
        )
        parts.append(
            build_bitstring_tlv(image_digest)
        )

    if not parts:
        return b""

    content = b"".join(parts)

    return (
        b"\xa0"
        + encode_length(len(content))
        + content
    )


def parse_override_block(block):
    nodes = parse_tlv_tree(block)

    if len(nodes) != 1:
        raise ValueError(
            "override block must contain one root TLV"
        )

    root = nodes[0]

    if not (
        root["tag_class"] == 2
        and root["constructed"]
        and root["tagnum"] == 0
    ):
        raise ValueError(
            "override root is not context-specific [0]"
        )

    result = {
        "header_hash": None,
        "image_hash": None,
    }

    children = root.get("children") or []

    for i, node in enumerate(children):
        if not (
            node["tag_class"] == 0
            and node["tagnum"] == 6
            and node["val"] is not None
        ):
            continue

        oid = decode_oid(node["val"])

        if i + 1 >= len(children):
            continue

        bs = children[i + 1]

        if not (
            bs["tag_class"] == 0
            and bs["tagnum"] == 3
            and bs["val"] is not None
        ):
            continue

        value = bs["val"]

        if len(value) < 1:
            continue

        if value[0] != 0:
            continue

        digest = value[1:]

        if oid == OID_IMAGE_HEADER_HASH:
            result["header_hash"] = digest

        elif oid == OID_IMAGE_HASH:
            result["image_hash"] = digest

    return result


def find_existing_override(der):
    """
    Find the existing effective A0 hash override.

    Only the first applicable override is treated as effective.
    """

    for node in iter_top_level_tlvs(der):
        if not (
            node["tag_class"] == 2
            and node["constructed"]
            and node["tagnum"] == 0
        ):
            continue

        block = der[node["off"]:node["end"]]

        try:
            parsed = parse_override_block(block)
        except Exception:
            continue

        if (
            parsed["header_hash"] is not None
            or parsed["image_hash"] is not None
        ):
            return {
                "off": node["off"],
                "end": node["end"],
                "block": block,
                "parsed": parsed,
            }

    return None


def replace_existing_override(
    der,
    header_digest,
    image_digest,
):
    """
    Replace the existing A0 block while preserving every byte
    outside that block.

    Returns:
        new_der, replaced, old_override
    """

    existing = find_existing_override(der)

    if existing is None:
        return der, False, None

    new_block = build_hash_override_block(
        header_digest,
        image_digest,
    )

    start = existing["off"]
    end = existing["end"]

    new_der = (
        der[:start]
        + new_block
        + der[end:]
    )

    return new_der, True, existing


def encode_der_root_with_insertion(der, insert_block):
    """
    Insert bytes at the beginning of the root DER content.

    Used only when there is no existing A0 override.
    """

    pmc = load_pmc()

    (
        tag_class,
        constructed,
        tagnum,
        tag_bytes,
        tag_len,
    ) = pmc.read_tag(der, 0)

    length_old, len_len = pmc.read_length(
        der,
        tag_len,
    )

    if length_old is None:
        raise ValueError(
            "indefinite-length root DER unsupported"
        )

    hdr_len = tag_len + len_len

    if hdr_len + length_old > len(der):
        raise ValueError(
            "root DER length exceeds available bytes"
        )

    rest = der[hdr_len:]

    new_len = length_old + len(insert_block)

    return (
        tag_bytes
        + encode_length(new_len)
        + insert_block
        + rest
    )


def reconstruct_cert2(
    original_der,
    original_cert_der,
    original_cert_rel,
    original_cert_end,
    header_digest,
    image_digest,
    legacy=False,
):
    """
    Construct the updated CERT2.

    Critical invariant:

        original_cert_der

    is a byte slice captured from the original CERT2 and is inserted
    unchanged into the new CERT2.

    The certificate is never reparsed and regenerated.
    """

    override = build_hash_override_block(
        header_digest,
        image_digest,
    )

    existing = find_existing_override(
        original_der
    )

    if existing is not None:
        old_start = existing["off"]
        old_end = existing["end"]

        # Preserve everything after the existing override exactly.
        suffix = original_der[old_end:]

        # The known certificate must still occur in that suffix.
        cert_pos = original_cert_rel - old_end

        if cert_pos < 0:
            raise ValueError(
                "certificate begins inside existing override"
            )

        if (
            cert_pos + len(original_cert_der)
            > len(suffix)
        ):
            raise ValueError(
                "certificate range no longer fits after override"
            )

        # Verify the known original certificate against the suffix.
        if (
            suffix[cert_pos:
                   cert_pos + len(original_cert_der)]
            != original_cert_der
        ):
            raise ValueError(
                "original certificate does not match "
                "the expected suffix"
            )

        # Preserve all bytes after the original override.
        new_der = override + suffix

        new_cert_rel = len(override) + cert_pos

    else:
        # No existing override.
        #
        # The original DER must itself contain the exact certificate
        # range we captured.
        if (
            original_der[
                original_cert_rel:
                original_cert_end
            ]
            != original_cert_der
        ):
            raise ValueError(
                "original certificate range changed before reconstruction"
            )

        if legacy:
            legacy_block = build_bitstring_tlv(
                original_cert_der
            )

            new_der = (
                legacy_block
                + override
                + original_der
            )

            new_cert_rel = (
                len(legacy_block)
                + len(override)
                + original_cert_rel
            )

        else:
            new_der = (
                override
                + original_der
            )

            new_cert_rel = (
                len(override)
                + original_cert_rel
            )

    # Optional legacy wrapper for an already-overridden CERT2.
    if legacy and existing is not None:
        legacy_block = build_bitstring_tlv(
            original_cert_der
        )

        new_der = (
            legacy_block
            + new_der
        )

        new_cert_rel += len(legacy_block)

    return new_der, new_cert_rel


def replace_cert2_blob(
    data,
    c_blob_off,
    c_off,
    c_hdr,
    new_blob,
):
    """
    Replace CERT2's aligned data region and update dsize.

    This operation may resize the logical CERT2, which can shift
    subsequent partitions. The resulting image is reparsed afterward.
    """

    new_dsize = len(new_blob)

    if c_hdr.align_sz <= 0:
        raise ValueError(
            f"invalid CERT2 alignment: {c_hdr.align_sz}"
        )

    old_padded = c_hdr.padded_data_size()

    new_padded = roundup(
        new_dsize,
        c_hdr.align_sz,
    )

    padded_blob = (
        new_blob
        + b"\x00" * (new_padded - new_dsize)
    )

    out = bytearray(data)

    out[
        c_blob_off:
        c_blob_off + old_padded
    ] = padded_blob

    # part_hdr_t.dsize
    struct.pack_into(
        "<I",
        out,
        c_off + 4,
        new_dsize,
    )

    return bytes(out)


def identify_target_part(parts, cert2_off):
    """
    Select the closest preceding non-certificate partition.

    For the observed MD1 layout:

        md1rom
        CERT1
        CERT2
    """

    cert2_pos = None

    for pos, entry in enumerate(parts):
        if entry[1] == cert2_off:
            cert2_pos = pos
            break

    if cert2_pos is None:
        return None

    for pos in range(cert2_pos - 1, -1, -1):
        entry = parts[pos]
        hdr = entry[4]

        if not hdr.is_certificate:
            return entry

    return None


def calculate_hashes(data, target_entry):
    (
        t_idx,
        t_off,
        t_data_off,
        t_next_off,
        t_hdr,
    ) = target_entry

    # Established target behavior: hash exactly the 512-byte
    # part_hdr_t.
    header_bytes = data[
        t_off:
        t_off + PART_HDR_SIZE
    ]

    padded_size = t_hdr.padded_data_size()

    payload_end = (
        t_data_off
        + padded_size
    )

    if payload_end > len(data):
        raise ValueError(
            "target payload exceeds image"
        )

    payload_bytes = data[
        t_data_off:
        payload_end
    ]

    return (
        hashlib.sha256(header_bytes).digest(),
        hashlib.sha256(payload_bytes).digest(),
    )


def extract_existing_hashes(der):
    hdr_bit, hdr_oid_rel = find_oid_bitstring(
        der,
        OID_IMAGE_HEADER_HASH,
    )

    img_bit, img_oid_rel = find_oid_bitstring(
        der,
        OID_IMAGE_HASH,
    )

    old_hdr = None
    old_img = None

    if hdr_bit is not None:
        if len(hdr_bit) < 1:
            raise ValueError(
                "invalid header hash BIT STRING"
            )

        if hdr_bit[0] != 0:
            raise ValueError(
                "header hash BIT STRING has nonzero unused bits"
            )

        old_hdr = hdr_bit[1:]

    if img_bit is not None:
        if len(img_bit) < 1:
            raise ValueError(
                "invalid image hash BIT STRING"
            )

        if img_bit[0] != 0:
            raise ValueError(
                "image hash BIT STRING has nonzero unused bits"
            )

        old_img = img_bit[1:]

    return (
        old_hdr,
        hdr_oid_rel,
        old_img,
        img_oid_rel,
    )


def digest_algorithm(digest):
    if digest is None:
        return "unknown"

    if len(digest) == 32:
        return "sha256"

    if len(digest) == 48:
        return "sha384"

    return f"unknown-{len(digest) * 8}"


def verify_effective_hashes(
    der,
    expected_header,
    expected_image,
):
    actual_header, _, actual_image, _ = (
        extract_existing_hashes(der)
    )

    if actual_header != expected_header:
        raise ValueError(
            "effective CERT2 header hash mismatch"
        )

    if actual_image != expected_image:
        raise ValueError(
            "effective CERT2 image hash mismatch"
        )


def verify_certificate_unchanged(
    new_blob,
    original_cert_der,
    expected_cert_rel,
):
    """
    Verify the exact certificate bytes at the exact reconstructed
    location.
    """

    end = (
        expected_cert_rel
        + len(original_cert_der)
    )

    if end > len(new_blob):
        raise ValueError(
            "reconstructed certificate exceeds CERT2"
        )

    actual = new_blob[
        expected_cert_rel:end
    ]

    if actual != original_cert_der:
        raise ValueError(
            "underlying CERT2 certificate changed"
        )


def verify_partition_layout(data):
    parts = parse_part_headers(data)

    if not parts:
        raise ValueError(
            "no valid partition headers after reconstruction"
        )

    for (
        idx,
        off,
        data_off,
        next_off,
        hdr,
    ) in parts:

        if data_off != off + PART_HDR_SIZE:
            raise ValueError(
                f"partition {idx} has invalid data offset"
            )

        if next_off > len(data):
            raise ValueError(
                f"partition {idx} exceeds image size"
            )

    return parts


def print_partition_table(parts):
    print()
    print("Partitions:")

    for (
        idx,
        off,
        data_off,
        next_off,
        hdr,
    ) in parts:
        print(
            f"[{idx:02d}] "
            f"hdr=0x{off:08x} "
            f"data=0x{data_off:08x} "
            f"dsize={hdr.dsize:10d} "
            f"padded={hdr.padded_data_size():10d} "
            f"align={hdr.align_sz:6d} "
            f"type=0x{hdr.img_type:08x} "
            f"name='{hdr.name}'"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "MTK CERT2 hash extractor/updater"
        )
    )

    parser.add_argument(
        "image",
        help="input image",
    )

    parser.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="write updated image",
    )

    parser.add_argument(
        "-o",
        "--out",
        help=(
            "output path "
            "(default: <input>.signed)"
        ),
    )

    parser.add_argument(
        "--legacy",
        action="store_true",
        help=(
            "add the legacy BIT STRING containing the "
            "original CERT2 certificate"
        ),
    )

    args = parser.parse_args()

    path = Path(args.image)

    if not path.exists():
        print(
            "File not found:",
            path,
            file=sys.stderr,
        )
        sys.exit(2)

    data = path.read_bytes()

    print(
        f"Name: {path.name}  "
        f"Size: {len(data)}"
    )

    print(
        "SHA256:",
        hashlib.sha256(data).hexdigest(),
    )

    parts = parse_part_headers(data)

    if not parts:
        print(
            "No part_hdr_t headers found",
            file=sys.stderr,
        )
        sys.exit(1)

    print_partition_table(parts)

    # ------------------------------------------------------------
    # Locate CERT2.
    # ------------------------------------------------------------

    cert2_entry = None

    for entry in parts:
        if entry[4].is_cert2:
            cert2_entry = entry
            break

    if cert2_entry is None:
        print(
            "No CERT2 partition header found",
            file=sys.stderr,
        )
        sys.exit(1)

    (
        c_idx,
        c_off,
        c_blob_off,
        c_next_off,
        c_hdr,
    ) = cert2_entry

    der = data[
        c_blob_off:
        c_blob_off + c_hdr.dsize
    ]

    print()
    print(
        f"Found CERT2: "
        f"index={c_idx} "
        f"header=0x{c_off:08x} "
        f"blob=0x{c_blob_off:08x} "
        f"dsize={c_hdr.dsize} "
        f"0x{c_hdr.dsize:x} "
        f"align={c_hdr.align_sz}"
    )

    # ------------------------------------------------------------
    # Capture the original certificate BYTES before modification.
    # ------------------------------------------------------------

    try:
        (
            original_cert_der,
            original_cert_rel,
            original_cert_end,
        ) = find_original_cert2_der(der)

    except ValueError as exc:
        print(
            f"Unable to locate original CERT2 DER: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"Underlying CERT2 DER: "
        f"rel=0x{original_cert_rel:x} "
        f"size={len(original_cert_der)} "
        f"0x{len(original_cert_der):x}"
    )

    print(
        f"Underlying CERT2 DER end: "
        f"rel=0x{original_cert_end:x}"
    )

    # Immutable reference to the certificate.
    original_cert_sha256 = hashlib.sha256(
        original_cert_der
    ).hexdigest()

    print(
        "Underlying CERT2 DER SHA256:",
        original_cert_sha256,
    )

    # ------------------------------------------------------------
    # Existing hashes / override.
    # ------------------------------------------------------------

    (
        old_hdr_digest,
        hdr_oid_rel,
        old_img_digest,
        img_oid_rel,
    ) = extract_existing_hashes(der)

    print()

    if old_hdr_digest is not None:
        print(
            "Image Header Hash (existing):",
            old_hdr_digest.hex(),
        )
        print(
            "Header hash algorithm:",
            digest_algorithm(old_hdr_digest),
        )
        print(
            "Header hash OID rel:",
            f"0x{hdr_oid_rel:x}",
        )
    else:
        print(
            "Image Header Hash: NOT FOUND"
        )

    if old_img_digest is not None:
        print(
            "Image Hash (existing):",
            old_img_digest.hex(),
        )
        print(
            "Image hash algorithm:",
            digest_algorithm(old_img_digest),
        )
        print(
            "Image hash OID rel:",
            f"0x{img_oid_rel:x}",
        )
    else:
        print(
            "Image Hash: NOT FOUND"
        )

    existing_override = find_existing_override(der)

    if existing_override is not None:
        print()
        print(
            "Existing effective A0 hash override: "
            f"rel=0x{existing_override['off']:x} "
            f"size={existing_override['end'] - existing_override['off']}"
        )

        parsed = existing_override["parsed"]

        if parsed["header_hash"] is not None:
            print(
                "  override header hash:",
                parsed["header_hash"].hex(),
            )

        if parsed["image_hash"] is not None:
            print(
                "  override image hash:",
                parsed["image_hash"].hex(),
            )

    else:
        print()
        print(
            "No existing effective A0 hash override found."
        )

    # ------------------------------------------------------------
    # Locate associated image.
    # ------------------------------------------------------------

    target_part = identify_target_part(
        parts,
        c_off,
    )

    if target_part is None:
        print(
            "No target image partition found before CERT2",
            file=sys.stderr,
        )
        sys.exit(1)

    (
        t_idx,
        t_off,
        t_data_off,
        t_next_off,
        t_hdr,
    ) = target_part

    print()
    print(
        "Associated target partition:"
    )
    print(
        f"  index       : {t_idx}"
    )
    print(
        f"  name        : {t_hdr.name}"
    )
    print(
        f"  header      : 0x{t_off:08x}"
    )
    print(
        f"  payload     : 0x{t_data_off:08x}"
    )
    print(
        f"  dsize       : {t_hdr.dsize} "
        f"(0x{t_hdr.dsize:x})"
    )
    print(
        f"  padded size : {t_hdr.padded_data_size()} "
        f"(0x{t_hdr.padded_data_size():x})"
    )
    print(
        f"  alignment   : {t_hdr.align_sz}"
    )

    # ------------------------------------------------------------
    # Calculate hashes.
    # ------------------------------------------------------------

    (
        new_hdr_digest,
        new_img_digest,
    ) = calculate_hashes(
        data,
        target_part,
    )

    print()
    print(
        "Calculated Image Header Hash:"
    )
    print(
        " ",
        new_hdr_digest.hex(),
    )

    print(
        "Calculated Image Hash:"
    )
    print(
        " ",
        new_img_digest.hex(),
    )

    if old_hdr_digest is not None:
        print()
        print(
            "Existing header hash comparison:",
            "MATCH"
            if old_hdr_digest == new_hdr_digest
            else "DIFFERENT",
        )

    if old_img_digest is not None:
        print(
            "Existing image hash comparison:",
            "MATCH"
            if old_img_digest == new_img_digest
            else "DIFFERENT",
        )

    if not args.write:
        print()
        print(
            "No -w specified; analysis only."
        )
        return

    # ------------------------------------------------------------
    # Reconstruct CERT2.
    # ------------------------------------------------------------

    new_blob, new_cert_rel = reconstruct_cert2(
        der,
        original_cert_der,
        original_cert_rel,
        original_cert_end,
        new_hdr_digest,
        new_img_digest,
        legacy=args.legacy,
    )

    old_padded = c_hdr.padded_data_size()
    new_padded = roundup(
        len(new_blob),
        c_hdr.align_sz,
    )

    print()
    print(
        "CERT2 transformation:"
    )
    print(
        f"  old logical size : {len(der)} "
        f"(0x{len(der):x})"
    )
    print(
        f"  old padded size  : {old_padded} "
        f"(0x{old_padded:x})"
    )
    print(
        f"  new logical size : {len(new_blob)} "
        f"(0x{len(new_blob):x})"
    )
    print(
        f"  new padded size  : {new_padded} "
        f"(0x{new_padded:x})"
    )
    print(
        f"  logical delta    : "
        f"{len(new_blob) - len(der):+d}"
    )
    print(
        f"  padded delta     : "
        f"{new_padded - old_padded:+d}"
    )
    print(
        "  existing A0 replaced:",
        "YES" if existing_override is not None else "NO",
    )

    print(
        f"  reconstructed certificate rel: "
        f"0x{new_cert_rel:x}"
    )

    # ------------------------------------------------------------
    # Verify exact certificate preservation.
    # ------------------------------------------------------------

    verify_certificate_unchanged(
        new_blob,
        original_cert_der,
        new_cert_rel,
    )

    new_cert_sha256 = hashlib.sha256(
        new_blob[
            new_cert_rel:
            new_cert_rel + len(original_cert_der)
        ]
    ).hexdigest()

    if new_cert_sha256 != original_cert_sha256:
        print(
            "ERROR: certificate SHA256 changed",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        "  underlying cert   : unchanged"
    )
    print(
        "  certificate SHA256:",
        new_cert_sha256,
    )

    # ------------------------------------------------------------
    # Verify the generated CERT2 before touching the image.
    # ------------------------------------------------------------

    verify_effective_hashes(
        new_blob,
        new_hdr_digest,
        new_img_digest,
    )

    print(
        "  effective hashes  : verified"
    )

    # ------------------------------------------------------------
    # Replace the CERT2 partition.
    # ------------------------------------------------------------

    out_bytes = replace_cert2_blob(
        data,
        c_blob_off,
        c_off,
        c_hdr,
        new_blob,
    )

    # ------------------------------------------------------------
    # Reparse resulting partition table.
    # ------------------------------------------------------------

    try:
        new_parts = verify_partition_layout(
            out_bytes
        )

    except ValueError as exc:
        print(
            f"ERROR: resulting partition layout invalid: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------
    # Locate resulting CERT2.
    # ------------------------------------------------------------

    new_cert2_entry = None

    for entry in new_parts:
        if entry[4].is_cert2:
            new_cert2_entry = entry
            break

    if new_cert2_entry is None:
        print(
            "ERROR: CERT2 disappeared after reconstruction",
            file=sys.stderr,
        )
        sys.exit(1)

    (
        nc_idx,
        nc_off,
        nc_blob_off,
        nc_next_off,
        nc_hdr,
    ) = new_cert2_entry

    resulting_cert2 = out_bytes[
        nc_blob_off:
        nc_blob_off + nc_hdr.dsize
    ]

    # ------------------------------------------------------------
    # Verify final CERT2 hash values.
    # ------------------------------------------------------------

    verify_effective_hashes(
        resulting_cert2,
        new_hdr_digest,
        new_img_digest,
    )

    # ------------------------------------------------------------
    # Verify final certificate AGAIN using the original byte string.
    #
    # Do not rediscover it through DER parsing.
    # ------------------------------------------------------------

    final_existing = find_existing_override(
        resulting_cert2
    )

    if final_existing is None:
        print(
            "ERROR: resulting effective A0 override not found",
            file=sys.stderr,
        )
        sys.exit(1)

    final_a0_end = final_existing["end"]

    # For the normal non-legacy layout, certificate follows the A0.
    # For legacy mode, the certificate is after the legacy wrapper
    # and A0. Find the exact byte string using the known immutable
    # certificate bytes, not a generic SEQUENCE search.
    candidate_positions = []

    start = final_a0_end

    while True:
        pos = resulting_cert2.find(
            original_cert_der,
            start,
        )

        if pos < 0:
            break

        candidate_positions.append(pos)
        start = pos + 1

    if not candidate_positions:
        print(
            "ERROR: original certificate bytes not found "
            "in resulting CERT2",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(candidate_positions) != 1:
        print(
            "ERROR: original certificate occurs multiple times "
            "in resulting CERT2; refusing ambiguous verification",
            file=sys.stderr,
        )
        sys.exit(1)

    final_cert_rel = candidate_positions[0]

    final_cert = resulting_cert2[
        final_cert_rel:
        final_cert_rel + len(original_cert_der)
    ]

    if final_cert != original_cert_der:
        print(
            "ERROR: final underlying certificate changed",
            file=sys.stderr,
        )
        sys.exit(1)

    if hashlib.sha256(final_cert).hexdigest() != (
        original_cert_sha256
    ):
        print(
            "ERROR: final certificate SHA256 changed",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------
    # Verify CERT2 dsize / padding.
    # ------------------------------------------------------------

    if nc_hdr.dsize != len(new_blob):
        print(
            "ERROR: final CERT2 dsize mismatch",
            file=sys.stderr,
        )
        sys.exit(1)

    if nc_hdr.padded_data_size() != new_padded:
        print(
            "ERROR: final CERT2 padded size mismatch",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------
    # Write only after all checks pass.
    # ------------------------------------------------------------

    out_path = (
        Path(args.out)
        if args.out
        else path.with_suffix(
            path.suffix + ".signed"
        )
    )

    out_path.write_bytes(out_bytes)

    print()
    print(
        "All pre-write and post-reconstruction checks passed."
    )

    print(
        "Write complete:",
        out_path,
    )

    print(
        "Output size:",
        len(out_bytes),
    )

    print(
        "Output SHA256:",
        hashlib.sha256(out_bytes).hexdigest(),
    )

    print()
    print(
        "Final CERT2:"
    )
    print(
        f"  header        : 0x{nc_off:08x}"
    )
    print(
        f"  blob          : 0x{nc_blob_off:08x}"
    )
    print(
        f"  dsize         : {nc_hdr.dsize} "
        f"(0x{nc_hdr.dsize:x})"
    )
    print(
        f"  padded        : {nc_hdr.padded_data_size()} "
        f"(0x{nc_hdr.padded_data_size():x})"
    )
    print(
        f"  certificate   : rel=0x{final_cert_rel:x}"
    )

    print()
    print(
        "Final effective Image Header Hash:"
    )
    print(
        " ",
        new_hdr_digest.hex(),
    )

    print(
        "Final effective Image Hash:"
    )
    print(
        " ",
        new_img_digest.hex(),
    )

    print()
    print(
        "Final certificate SHA256:"
    )
    print(
        " ",
        hashlib.sha256(final_cert).hexdigest(),
    )

    print()
    print(
        "Final partition layout:"
    )

    print_partition_table(new_parts)


if __name__ == "__main__":
    main()
