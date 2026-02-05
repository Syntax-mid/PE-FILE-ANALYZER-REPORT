import math

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0
    length = len(data)

    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy
