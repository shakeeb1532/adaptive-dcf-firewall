import os
import binascii

from profiles_loader import load_profiles
from payload_crypto import KeyStore, SequenceManager, encrypt_payload, decrypt_payload
from stream_framing import frame_bytes, deframe
from traffic_mitigation import DeterministicPadder, PaddingPolicy
from artifact_log import ArtifactLogger


def _randkey():
    return binascii.hexlify(os.urandom(32)).decode("ascii")


def _setup_keys():
    os.environ["ADCF_KEY_K_BASE_OUT"] = _randkey()
    os.environ["ADCF_KEY_K_BASE_OUT_2"] = _randkey()
    os.environ["ADCF_KEY_K_HI_OUT"] = _randkey()
    os.environ["ADCF_KEY_K_HI_OUT_2"] = _randkey()


def test_frame_deframe_roundtrip():
    payload = b"abc" * 10
    framed = frame_bytes(payload)
    frames, rem = deframe(framed)
    assert rem == b""
    assert frames[0] == payload


def test_encrypt_decrypt_roundtrip():
    _setup_keys()
    profiles = load_profiles("profiles")
    profile = profiles["baseline"].raw
    policy_hash = profiles["baseline"].policy_hash
    ks = KeyStore.from_env()
    seq = SequenceManager()

    pt = b"payload-data-123"
    env = encrypt_payload(pt, profile, "baseline", policy_hash, ks, seq, "out", frame_plaintext=True)
    out = decrypt_payload(env, profile, policy_hash, ks, "in", frame_plaintext=True)
    assert out == pt


def test_padding_roundtrip():
    _setup_keys()
    ks = KeyStore.from_env()
    key = ks.get("k_base_out")
    padder = DeterministicPadder(key)
    policy = PaddingPolicy(enabled=True, min_pad_bytes=8, max_pad_bytes=16)
    pt = b"payload-data"
    padded = padder.pad(pt, policy)
    out = padder.unpad(padded)
    assert out == pt


def test_artifact_log_sealed(tmp_path):
    log_key = os.urandom(32)
    log_path = tmp_path / "payload_artifacts.log"
    logger = ArtifactLogger(str(log_path), log_key)
    rec = logger.write({"profile_id":"baseline","policy_hash":"x","direction":"out"}, b"env")
    assert rec.profile_id == "baseline"
