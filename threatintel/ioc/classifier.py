def classify_ioc(ioc_type, value):
    """
    Simple rule-based classification
    """
    score = 10

    if ioc_type == "ip":
        if value.startswith("192.") or value.startswith("10."):
            score = 5   # internal IP (less risky)
        else:
            score = 50  # external IP

    elif ioc_type == "cve":
        score = 90  # CVEs are serious

    elif ioc_type == "hash":
        score = 80  # malware hashes

    return score