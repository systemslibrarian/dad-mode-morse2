#!/usr/bin/env python3
"""
Dad's Morse — WAV Decode Test Suite

Synthesises WAV data using the same parameters as the JS app
(44100 Hz, 700 Hz tone, 60 ms unit), then runs the decode algorithm
and compares output.

Python 3 standard library only — no dependencies required.

Run:
    python3 test_decode.py
"""

import struct
import math
import sys

# ── WAV synthesis (mirrors JS app parameters) ──

SAMPLE_RATE = 44100
FREQ = 700
UNIT_MS = 60  # dot duration in milliseconds

DOT = UNIT_MS / 1000
DASH = UNIT_MS * 3 / 1000
ELEM_GAP = UNIT_MS / 1000
LETTER_GAP = UNIT_MS * 3 / 1000
WORD_GAP = UNIT_MS * 7 / 1000


def generate_tone(duration_s, freq=FREQ, amplitude=0.3):
    """Generate a sine wave tone."""
    n_samples = int(SAMPLE_RATE * duration_s)
    return [amplitude * math.sin(2 * math.pi * freq * i / SAMPLE_RATE) for i in range(n_samples)]


def generate_silence(duration_s):
    """Generate silence."""
    return [0.0] * int(SAMPLE_RATE * duration_s)


def morse_to_samples(morse_str):
    """Convert a Morse string to PCM samples (mirrors JS generateWAV)."""
    samples = []
    for c in morse_str:
        if c == '.':
            samples += generate_tone(DOT)
            samples += generate_silence(ELEM_GAP)
        elif c == '-':
            samples += generate_tone(DASH)
            samples += generate_silence(ELEM_GAP)
        elif c == ' ':
            samples += generate_silence(LETTER_GAP)
        elif c == '/':
            samples += generate_silence(WORD_GAP)
    return samples


def samples_to_wav_bytes(samples, stereo=False):
    """Pack samples into a WAV byte buffer."""
    n_channels = 2 if stereo else 1
    n_samples = len(samples)
    data_size = n_samples * n_channels * 2
    
    buf = bytearray()
    buf += b'RIFF'
    buf += struct.pack('<I', 36 + data_size)
    buf += b'WAVE'
    buf += b'fmt '
    buf += struct.pack('<I', 16)  # PCM
    buf += struct.pack('<H', 1)   # PCM format
    buf += struct.pack('<H', n_channels)
    buf += struct.pack('<I', SAMPLE_RATE)
    buf += struct.pack('<I', SAMPLE_RATE * n_channels * 2)
    buf += struct.pack('<H', n_channels * 2)
    buf += struct.pack('<H', 16)  # bits per sample
    buf += b'data'
    buf += struct.pack('<I', data_size)
    
    for s in samples:
        clamped = max(-1.0, min(1.0, s))
        val = int(clamped * 32767) if clamped >= 0 else int(clamped * 32768)
        packed = struct.pack('<h', val)
        buf += packed
        if stereo:
            buf += packed  # duplicate to second channel
    
    return bytes(buf)


# ── WAV decoder (mirrors JS decodeWav) ──

def decode_wav(wav_bytes):
    """Decode WAV bytes to Morse string (mirrors JS algorithm)."""
    # Parse WAV header
    assert wav_bytes[:4] == b'RIFF', "Not a WAV file"
    assert wav_bytes[8:12] == b'WAVE', "Not a WAV file"
    
    # Find data chunk
    pos = 12
    while pos < len(wav_bytes) - 8:
        chunk_id = wav_bytes[pos:pos+4]
        chunk_size = struct.unpack('<I', wav_bytes[pos+4:pos+8])[0]
        if chunk_id == b'fmt ':
            n_channels = struct.unpack('<H', wav_bytes[pos+10:pos+12])[0]
            sample_rate = struct.unpack('<I', wav_bytes[pos+12:pos+16])[0]
            bits_per_sample = struct.unpack('<H', wav_bytes[pos+22:pos+24])[0]
            pos += 8 + chunk_size
        elif chunk_id == b'data':
            data_start = pos + 8
            data_end = data_start + chunk_size
            break
        else:
            pos += 8 + chunk_size
    else:
        raise ValueError("No data chunk found")
    
    # Read samples (mix to mono if stereo)
    bytes_per_sample = bits_per_sample // 8
    n_samples = chunk_size // (bytes_per_sample * n_channels)
    samples = []
    for i in range(n_samples):
        offset = data_start + i * bytes_per_sample * n_channels
        if bytes_per_sample == 2:
            val = struct.unpack('<h', wav_bytes[offset:offset+2])[0] / 32768.0
            if n_channels == 2:
                val2 = struct.unpack('<h', wav_bytes[offset+2:offset+4])[0] / 32768.0
                val = (val + val2) / 2
        samples.append(val)
    
    # Energy detection in 5ms frames
    frame_ms = 5
    frame_samples = int(sample_rate * frame_ms / 1000)
    n_frames = len(samples) // frame_samples
    
    energy = []
    for f in range(n_frames):
        start = f * frame_samples
        rms = math.sqrt(sum(samples[start + i] ** 2 for i in range(frame_samples)) / frame_samples)
        energy.append(rms)
    
    # Threshold at 15% of 95th percentile
    sorted_energy = sorted(energy)
    threshold = sorted_energy[int(len(sorted_energy) * 0.95)] * 0.15
    if threshold < 1e-5:
        raise ValueError("No signal detected")
    
    binary = [1 if e > threshold else 0 for e in energy]
    
    # Run-length encode
    runs = []
    if binary:
        cur = binary[0]
        count = 1
        for i in range(1, len(binary)):
            if binary[i] == cur:
                count += 1
            else:
                runs.append((cur, count * frame_ms))
                cur = binary[i]
                count = 1
        runs.append((cur, count * frame_ms))
    
    # Trim leading/trailing silence
    while runs and runs[0][0] == 0:
        runs.pop(0)
    while runs and runs[-1][0] == 0:
        runs.pop()
    
    if not runs:
        return ""
    
    # Estimate unit from on-durations
    on_durs = sorted([ms for val, ms in runs if val == 1])
    unit = 60  # default
    
    if on_durs:
        med = on_durs[len(on_durs) // 2]
        max_ratio = 1
        split_idx = -1
        for i in range(len(on_durs) - 1):
            ratio = on_durs[i + 1] / on_durs[i] if on_durs[i] > 0 else 1
            if ratio > max_ratio:
                max_ratio = ratio
                split_idx = i + 1
        
        if max_ratio > 1.8 and split_idx > 0:
            dots = on_durs[:split_idx]
            unit = round(sum(dots) / len(dots))
        elif med > 100:
            unit = round(med / 3)
        else:
            unit = med
    
    unit = max(20, unit)
    
    # Classify runs into morse
    morse = ""
    for val, ms in runs:
        if val == 1:
            morse += "." if ms < unit * 2 else "-"
        else:
            if ms < unit * 2:
                continue
            if ms < unit * 5:
                morse += " "
            else:
                morse += " / "
    
    # Clean up
    import re
    morse = morse.strip()
    morse = re.sub(r'\s*/\s*', ' / ', morse)
    morse = re.sub(r'  +', ' ', morse)
    return morse


# ── Test runner ──

passed = 0
failed = 0
failures = []


def test(num, name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  ✅ {num}. {name}")
    except Exception as e:
        failed += 1
        failures.append((num, name, str(e)))
        print(f"  ❌ {num}. {name} — {e}")


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: expected '{b}', got '{a}'" if msg else f"expected '{b}', got '{a}'")


def roundtrip(morse_str, label=""):
    """Encode morse → WAV → decode morse, return decoded string."""
    samples = morse_to_samples(morse_str)
    wav = samples_to_wav_bytes(samples)
    decoded = decode_wav(wav)
    return decoded


# ── Tests ──

print("\n🔊 Dad's Morse v5 — WAV Decode Test Suite\n")
print("── Basic Decode ──")

test(1, "Mixed dots/dashes: A B C D E F", lambda: (
    assert_eq(roundtrip(".- -... -.-. -.. . ..-."), ".- -... -.-. -.. . ..-.")
))

test(2, "SOS-like pattern", lambda: (
    assert_eq(roundtrip("... --- ..."), "... --- ...")
))

test(3, "Digits 1 2 3 4", lambda: (
    assert_eq(roundtrip(".---- ..--- ...-- ....-"), ".---- ..--- ...-- ....-")
))

test(4, "All-dashes (hex 0 = -----)", lambda: (
    assert_eq(roundtrip("----- ----- -----"), "----- ----- -----")
))

test(5, "All-dots (hex 5 = .....)", lambda: (
    assert_eq(roundtrip("..... ..... ....."), "..... ..... .....")
))

test(6, "Single character", lambda: (
    assert_eq(roundtrip(".-"), ".-")
))

test(7, "Dash-heavy mixed pattern", lambda: (
    assert_eq(roundtrip(".---- ----- .---- -----"), ".---- ----- .---- -----")
))

print("\n── Advanced Decode ──")

test(8, "Leading/trailing silence preserved", lambda: (
    (lambda: (
        samples := [0.0] * 5000 + morse_to_samples(".- -...") + [0.0] * 5000,
        wav := samples_to_wav_bytes(samples),
        decoded := decode_wav(wav),
        assert_eq(decoded, ".- -...")
    ))()
))

test(9, "Stereo WAV decodes same as mono", lambda: (
    (lambda: (
        morse := ".- -... -.-.",
        samples := morse_to_samples(morse),
        mono_wav := samples_to_wav_bytes(samples, stereo=False),
        stereo_wav := samples_to_wav_bytes(samples, stereo=True),
        mono_decoded := decode_wav(mono_wav),
        stereo_decoded := decode_wav(stereo_wav),
        assert_eq(mono_decoded, stereo_decoded, "Stereo mismatch")
    ))()
))

test(10, "All 16 hex Morse chars round-trip", lambda: (
    (lambda: (
        hex_morse := {
            '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', 'A': '.-', 'B': '-...',
            'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.'
        },
        morse_str := ' '.join(hex_morse.values()),
        decoded := roundtrip(morse_str),
        assert_eq(decoded, morse_str)
    ))()
))

test(11, "Long cipher-like hex payload", lambda: (
    (lambda: (
        # Simulate: 0123456789ABCDEF → their morse representations
        codes := ['-----', '.----', '..---', '...--', '....-', '.....',
                  '-....', '--...', '---..', '----.', '.-', '-...',
                  '-.-.', '-..', '.', '..-.'],
        morse_str := ' '.join(codes * 3),
        decoded := roundtrip(morse_str),
        assert_eq(decoded, morse_str)
    ))()
))

test(12, "Rapid alternating dots and dashes (A B A B)", lambda: (
    assert_eq(roundtrip(".- -... .- -..."), ".- -... .- -...")
))

test(13, "Word gap / detection", lambda: (
    # Word gaps are 7 units — should appear as " / "
    (lambda: (
        samples := (
            morse_to_samples(".") +
            generate_silence(WORD_GAP) +
            morse_to_samples("-")
        ),
        wav := samples_to_wav_bytes(samples),
        decoded := decode_wav(wav),
        assert_eq("/" in decoded, True, "Word gap not detected")
    ))()
))

print("\n── Variable Speed ──")

test(14, "Faster unit (30ms)", lambda: (
    (lambda: (
        # Generate at half speed
        fast_dot := 30 / 1000,
        fast_dash := 90 / 1000,
        fast_gap := 30 / 1000,
        fast_letter := 90 / 1000,
        samples := (
            generate_tone(fast_dot) + generate_silence(fast_gap) +   # .
            generate_tone(fast_dash) + generate_silence(fast_gap) +  # -
            generate_silence(fast_letter) +
            generate_tone(fast_dash) + generate_silence(fast_gap) +  # -
            generate_tone(fast_dot) + generate_silence(fast_gap) +   # .
            generate_tone(fast_dot) + generate_silence(fast_gap) +   # .
            generate_tone(fast_dot) + generate_silence(fast_gap)     # .
        ),
        wav := samples_to_wav_bytes(samples),
        decoded := decode_wav(wav),
        assert_eq(decoded, ".- -...")
    ))()
))

test(15, "Slower unit (120ms)", lambda: (
    (lambda: (
        slow_dot := 120 / 1000,
        slow_dash := 360 / 1000,
        slow_gap := 120 / 1000,
        slow_letter := 360 / 1000,
        samples := (
            generate_tone(slow_dot) + generate_silence(slow_gap) +
            generate_tone(slow_dash) + generate_silence(slow_gap) +
            generate_silence(slow_letter) +
            generate_tone(slow_dash) + generate_silence(slow_gap) +
            generate_tone(slow_dot) + generate_silence(slow_gap) +
            generate_tone(slow_dot) + generate_silence(slow_gap) +
            generate_tone(slow_dot) + generate_silence(slow_gap)
        ),
        wav := samples_to_wav_bytes(samples),
        decoded := decode_wav(wav),
        assert_eq(decoded, ".- -...")
    ))()
))

test(16, "Empty signal raises error", lambda: (
    (lambda: (
        wav := samples_to_wav_bytes([0.0] * 10000),
        raised := False,
    ))() or
    (lambda: exec("raised = False\ntry:\n    decode_wav(samples_to_wav_bytes([0.0] * 10000))\nexcept ValueError:\n    raised = True\nassert raised, 'Should raise on empty signal'", {"decode_wav": decode_wav, "samples_to_wav_bytes": samples_to_wav_bytes}))()
))

# ── Results ──

print("\n" + "═" * 50)
print(f"  Results: {passed} passed, {failed} failed, {passed + failed} total")
if failures:
    print("\n  Failures:")
    for num, name, err in failures:
        print(f"    {num}. {name}: {err}")
print("═" * 50 + "\n")

sys.exit(1 if failed > 0 else 0)
