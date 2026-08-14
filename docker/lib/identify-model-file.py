#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# identify-model-file.py — read one AI model file and write the CycloneDX ML-BOM
# that describes it, using nothing but the file itself.
#
# Usage: identify-model-file.py <model_file> <out.json> [version] [scan_name]
#
# Why: the AI path so far starts from a HuggingFace model id, so everything the
# SBOM says comes from the model card the Hub serves. A model file that is not
# on the Hub — a supplier's delivery, an internal fine-tune, an air-gapped copy
# — has no card to read, and there was no way to scan it at all. This reads the
# file's own header instead.
#
# What each format yields differs, and the difference is reported rather than
# smoothed over:
#   GGUF         name, license, architecture, quantization, tensor count
#   safetensors  tensor count, dtypes, parameter count, and whatever the
#                optional __metadata__ block declares (often nothing)
#   pytorch-zip  the archive layout, and that the weights are pickle-format
#   pickle       that the weights are pickle-format
#   npz          the member list
#   onnx         the format alone (deep metadata needs a protobuf parser)
# A field the file does not carry is left out. Guessing a license or a model
# name onto a supply-chain document is worse than an honest blank.
#
# Reads the header, not the weights: a multi-gigabyte file is opened, parsed
# through its metadata section (array values are seeked past, never read), and
# closed. Only the SHA-256 walks the whole file, because an integrity hash of
# the first megabyte would be worthless.
#
# Deliberately stdlib-only, so it runs in the base image with no new dependency
# and works offline. The pickle SECURITY verdict is not here — this only records
# that a file is pickle-format; opcode analysis is a separate step.

import datetime
import hashlib
import json
import os
import struct
import sys
import urllib.parse
import zipfile

# Header caps. A model file whose declared metadata section runs past these is
# treated as unreadable rather than followed: the numbers come from the file
# itself, so an absurd length is either corruption or a hostile file, and both
# deserve the same refusal.
MAX_STRING = 4 * 1024 * 1024        # one metadata string
MAX_KV_PAIRS = 100000               # GGUF key/value pairs
MAX_ST_HEADER = 128 * 1024 * 1024   # safetensors JSON header
HASH_BLOCK = 4 * 1024 * 1024

# Extension -> the format it claims to be. Used only to compare against what the
# magic bytes actually say; the magic wins whenever the two disagree.
EXT_CLAIMS = {
    ".gguf": "gguf",
    ".safetensors": "safetensors",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".bin": "pickle",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".ckpt": "pytorch",
    ".npz": "npz",
    ".npy": "npy",
    ".onnx": "onnx",
}

# The formats whose weights are a Python pickle, i.e. the ones that execute code
# on load. Recorded so the risk step can act on it without re-sniffing.
PICKLE_FORMATS = ("pickle", "pytorch-zip")

GGUF_MAGIC = b"GGUF"
NPY_MAGIC = b"\x93NUMPY"
ZIP_MAGIC = b"PK\x03\x04"

# GGUF value types that carry a fixed-width payload, and how many bytes each is.
GGUF_FIXED = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
GGUF_STRING = 8
GGUF_ARRAY = 9

# GGUF keys worth lifting into the component, mapped to the property suffix they
# become. Everything else in the header stays in the file.
GGUF_KEYS = {
    "general.name": "name",
    "general.license": "license",
    "general.architecture": "architecture",
    "general.quantization_version": "quantization",
    "general.version": "modelVersion",
    "general.organization": "organization",
    "general.basename": "basename",
    "general.size_label": "sizeLabel",
}


def read_head(path, size=64):
    """First bytes of the file, short read tolerated (a tiny file is still a file)."""
    with open(path, "rb") as handle:
        return handle.read(size)


def _gguf_string(handle):
    raw = handle.read(8)
    if len(raw) < 8:
        raise ValueError("truncated string length")
    (length,) = struct.unpack("<Q", raw)
    if length > MAX_STRING:
        raise ValueError("string length %d over cap" % length)
    data = handle.read(length)
    if len(data) < length:
        raise ValueError("truncated string body")
    return data.decode("utf-8", "replace")


def _gguf_skip_value(handle, vtype):
    """Advance past one value. Arrays are seeked, never materialized."""
    if vtype in GGUF_FIXED:
        handle.seek(GGUF_FIXED[vtype], os.SEEK_CUR)
        return
    if vtype == GGUF_STRING:
        _gguf_string(handle)
        return
    if vtype == GGUF_ARRAY:
        raw = handle.read(12)
        if len(raw) < 12:
            raise ValueError("truncated array header")
        elem_type, count = struct.unpack("<IQ", raw)
        if elem_type in GGUF_FIXED:
            handle.seek(GGUF_FIXED[elem_type] * count, os.SEEK_CUR)
        elif elem_type == GGUF_STRING:
            # A token vocabulary is hundreds of thousands of strings; each one
            # has to be stepped over individually because they are not fixed
            # width. Reading the lengths only, so this stays cheap.
            for _ in range(count):
                raw = handle.read(8)
                if len(raw) < 8:
                    raise ValueError("truncated array string")
                (length,) = struct.unpack("<Q", raw)
                if length > MAX_STRING:
                    raise ValueError("array string over cap")
                handle.seek(length, os.SEEK_CUR)
        else:
            raise ValueError("unsupported array element type %d" % elem_type)
        return
    raise ValueError("unsupported value type %d" % vtype)


def _gguf_read_value(handle, vtype):
    """Read a value we actually want. Only scalars and strings are lifted."""
    if vtype == GGUF_STRING:
        return _gguf_string(handle)
    if vtype in (4, 5):
        return str(struct.unpack("<i" if vtype == 5 else "<I", handle.read(4))[0])
    if vtype in (10, 11):
        return str(struct.unpack("<q" if vtype == 11 else "<Q", handle.read(8))[0])
    if vtype in (0, 1, 7):
        return str(struct.unpack("<b" if vtype == 1 else "<B", handle.read(1))[0])
    if vtype in (2, 3):
        return str(struct.unpack("<h" if vtype == 3 else "<H", handle.read(2))[0])
    _gguf_skip_value(handle, vtype)
    return None


def parse_gguf(path):
    """GGUF header: version, tensor count, and the general.* metadata keys.

    Partial results are kept. A header that stops making sense half way through
    still told us the version and whatever keys came before the damage, and
    those are facts about the file.
    """
    out = {}
    with open(path, "rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            return out
        version, tensor_count, kv_count = struct.unpack("<IQQ", header[4:24])
        out["ggufVersion"] = str(version)
        out["tensors"] = str(tensor_count)
        if kv_count > MAX_KV_PAIRS:
            return out
        try:
            for _ in range(kv_count):
                key = _gguf_string(handle)
                raw = handle.read(4)
                if len(raw) < 4:
                    break
                (vtype,) = struct.unpack("<I", raw)
                if key in GGUF_KEYS:
                    value = _gguf_read_value(handle, vtype)
                    if value:
                        out[GGUF_KEYS[key]] = value
                else:
                    _gguf_skip_value(handle, vtype)
        except (ValueError, struct.error, OSError):
            out["headerTruncated"] = "true"
    return out


def parse_safetensors(path):
    """safetensors header: the JSON blob in front of the tensor data."""
    out = {}
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        raw = handle.read(8)
        if len(raw) < 8:
            return out
        (header_len,) = struct.unpack("<Q", raw)
        if header_len == 0 or header_len > MAX_ST_HEADER or header_len + 8 > size:
            out["headerTruncated"] = "true"
            return out
        try:
            header = json.loads(handle.read(header_len).decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            out["headerTruncated"] = "true"
            return out
    if not isinstance(header, dict):
        return out

    meta = header.get("__metadata__")
    if isinstance(meta, dict):
        # Only these keys are conventional enough to lift. Everything else in
        # __metadata__ is producer-specific and would be noise on a component.
        for key, prop in (("license", "license"), ("modelspec.title", "name"),
                          ("format", "weightFormat"), ("modelspec.author", "organization")):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                out[prop] = value.strip()

    tensors = 0
    params = 0
    dtypes = set()
    for name, spec in header.items():
        if name == "__metadata__" or not isinstance(spec, dict):
            continue
        tensors += 1
        dtype = spec.get("dtype")
        if isinstance(dtype, str):
            dtypes.add(dtype)
        shape = spec.get("shape")
        if isinstance(shape, list) and all(isinstance(d, int) and d >= 0 for d in shape):
            count = 1
            for dim in shape:
                count *= dim
            params += count
    out["tensors"] = str(tensors)
    if params:
        out["parameters"] = str(params)
    if dtypes:
        out["dtypes"] = ",".join(sorted(dtypes))
    return out


def inspect_zip(path):
    """Tell a torch archive from an npz, and describe what is inside either."""
    out = {}
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return "unknown", out
    out["archiveMembers"] = str(len(names))
    if any(n.endswith("data.pkl") for n in names):
        return "pytorch-zip", out
    npy = [n for n in names if n.endswith(".npy")]
    if npy:
        out["arrays"] = str(len(npy))
        return "npz", out
    return "unknown", out


def sniff_format(path, head):
    """What the file actually is, decided by content and not by its name."""
    extra = {}
    if head.startswith(GGUF_MAGIC):
        return "gguf", extra
    if head.startswith(ZIP_MAGIC):
        return inspect_zip(path)
    if head.startswith(NPY_MAGIC):
        return "npy", extra
    # A pickle stream opens with the PROTO opcode (0x80) and its version byte.
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 6:
        return "pickle", extra
    # safetensors has no magic: the first 8 bytes are the header length, and the
    # byte right after them opens the JSON object. Check that shape before
    # believing it, so an arbitrary file does not become "safetensors".
    if len(head) >= 9:
        (header_len,) = struct.unpack("<Q", head[:8])
        if 2 <= header_len <= MAX_ST_HEADER and head[8:9] == b"{":
            try:
                if header_len + 8 <= os.path.getsize(path):
                    return "safetensors", extra
            except OSError:
                pass
    # ONNX is protobuf with no magic of its own. Field 1 (ir_version) as the
    # first varint is the closest thing to a marker, and it is only trusted when
    # the extension agrees — protobuf shapes are too generic to claim alone.
    if head[:1] == b"\x08" and os.path.splitext(path)[1].lower() == ".onnx":
        return "onnx", extra
    return "unknown", extra


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(HASH_BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def spdx_shaped(value):
    """Keep a license string only if it looks like an identifier or a name.

    GGUF and safetensors both hold free text here. A short token (apache-2.0,
    MIT) is worth carrying; a paragraph of license prose is not an id and is
    dropped rather than pushed into a field that means "declared license".
    """
    text = (value or "").strip()
    if not text or len(text) > 64 or "\n" in text:
        return ""
    return text


def build_bom(path, version, scan_name, fmt, facts, digest):
    file_name = os.path.basename(path)
    size = os.path.getsize(path)

    name = facts.get("name") or os.path.splitext(file_name)[0]
    props = [{"name": "bomlens:modelfile:format", "value": fmt},
             {"name": "bomlens:modelfile:fileName", "value": file_name},
             {"name": "bomlens:modelfile:size", "value": str(size)}]

    claimed = EXT_CLAIMS.get(os.path.splitext(file_name)[1].lower())
    # "pytorch" is the claim both a raw pickle and a zip archive can satisfy,
    # so it matches either of the two real formats rather than one.
    matched = fmt == claimed or (claimed == "pytorch" and fmt in ("pytorch-zip", "pickle")) \
        or (claimed == "pickle" and fmt == "pytorch-zip")
    if claimed and not matched:
        props.append({"name": "bomlens:modelfile:extensionMismatch", "value": "true"})
        props.append({"name": "bomlens:modelfile:claimedFormat", "value": claimed})

    if fmt in PICKLE_FORMATS:
        # Same property enrich-aibom.sh stamps from the Hub file listing, so a
        # consumer counting pickle-format weights does not care where the file
        # came from.
        props.append({"name": "bomlens:weights:pickleFiles", "value": "1"})

    for key in ("ggufVersion", "architecture", "quantization", "tensors", "parameters",
                "dtypes", "weightFormat", "organization", "basename", "sizeLabel",
                "modelVersion", "archiveMembers", "arrays", "headerTruncated"):
        if facts.get(key):
            props.append({"name": "bomlens:modelfile:" + key, "value": facts[key]})

    component = {
        "type": "machine-learning-model",
        "bom-ref": "model-file:" + digest[:16],
        "name": name,
        "version": version,
        # pkg:generic is the purl type for something distributed as a file
        # rather than through a package registry, which is exactly what this is.
        # The checksum qualifier is what makes it identify this artifact and not
        # merely a name — there is no registry to resolve the name against.
        "purl": "pkg:generic/%s@%s?checksum=sha256:%s" % (
            urllib.parse.quote(name, safe=""),
            urllib.parse.quote(version, safe=""),
            digest),
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": props,
    }

    license_text = spdx_shaped(facts.get("license"))
    if license_text:
        component["licenses"] = [{"license": {"name": license_text}}]

    # Only what the file actually declared. An empty card is not written: a
    # modelCard key with nothing in it reads as "the card was collected".
    card_params = {}
    if facts.get("architecture"):
        card_params["architectureFamily"] = facts["architecture"]
    if card_params:
        component["modelCard"] = {"modelParameters": card_params}

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        # Derived from the file's own hash: re-scanning the same file yields the
        # same document identifier, which is what --byte-stable output needs.
        "serialNumber": "urn:uuid:%s-%s-%s-%s-%s" % (
            digest[0:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]),
        "version": 1,
        "metadata": {
            # Written here because nothing else in the pipeline does: the other
            # modes inherit a timestamp from the generator that produced their
            # SBOM (cdxgen, syft, the AIBOM generator), and this path has no
            # such generator. --byte-stable pins it afterwards in normalize.
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "bom-ref": "scan:" + digest[:16],
                "name": scan_name,
                "version": version,
            },
        },
        "components": [component],
        # One real edge: the scan is of this model file. A model file has no
        # dependencies of its own to declare, and an absent graph would be read
        # as "we did not look" rather than "there is nothing below it".
        "dependencies": [
            {"ref": "scan:" + digest[:16], "dependsOn": ["model-file:" + digest[:16]]},
            {"ref": "model-file:" + digest[:16], "dependsOn": []},
        ],
    }


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: identify-model-file.py <model_file> <out.json> "
                         "[version] [scan_name]\n")
        return 2
    path = sys.argv[1]
    out_path = sys.argv[2]
    version = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "unknown"
    scan_name = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else os.path.basename(path)

    if not os.path.isfile(path):
        sys.stderr.write("[modelfile] not a file: %s\n" % path)
        return 1
    if os.path.getsize(path) == 0:
        sys.stderr.write("[modelfile] file is empty: %s\n" % path)
        return 1

    head = read_head(path)
    fmt, facts = sniff_format(path, head)
    if fmt == "gguf":
        facts.update(parse_gguf(path))
    elif fmt == "safetensors":
        facts.update(parse_safetensors(path))

    if fmt == "unknown":
        # Refuse rather than emit a model component for a file we could not
        # identify: an SBOM saying "machine-learning-model" about an unread file
        # is a false statement, and the upload form should send it elsewhere.
        sys.stderr.write("[modelfile] ERROR: not a recognized model file: %s\n"
                         % os.path.basename(path))
        sys.stderr.write("[modelfile]   Recognized: GGUF, safetensors, PyTorch (.pt/.pth/.ckpt),\n")
        sys.stderr.write("[modelfile]   pickle, npz, npy, ONNX. A model directory or archive\n")
        sys.stderr.write("[modelfile]   should be scanned as a source folder instead.\n")
        return 3

    digest = sha256_file(path)
    bom = build_bom(path, version, scan_name, fmt, facts, digest)

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(bom, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    told = [k for k in ("license", "architecture", "parameters", "tensors") if facts.get(k)]
    sys.stderr.write("[modelfile] %s: %s, %s\n" % (
        os.path.basename(path), fmt,
        ("read " + ", ".join(told)) if told else "no header metadata declared"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
